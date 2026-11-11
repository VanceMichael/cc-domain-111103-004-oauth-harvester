"""采集 worker、分页台账与逐组织监督的集成测试。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.auth import AuthStatus
from app.coordinator import RefreshCoordinator
from app.harvester import HarvestWorker, Supervisor
from app.oauth import load_grant_records
from app.secrets import RedactingFilter
from app.storage import AuthStore, HarvestStore
from app.token_service import MockDataApi, MockTokenService


class FixedClock:
    def __init__(self, start: int = 1_800_000_000) -> None:
        self.value = start

    def now(self) -> int:
        return self.value


class HarvestHarness:
    def __init__(self, page_size: int = 3, total_pages: int = 4) -> None:
        self.tmp = TemporaryDirectory()
        root = Path(self.tmp.name)
        self.clock = FixedClock()
        self.records = load_grant_records()
        self.service = MockTokenService(self.clock)
        self.service.seed(self.records)
        self.data_api = MockDataApi(
            self.clock, page_size=page_size, total_pages=total_pages
        ).bind(self.service)
        secrets = [
            s
            for r in self.records.values()
            for s in (r.access_token, r.refresh_token)
        ]
        self.auth_store = AuthStore(root / "auth")
        self.auth_store.bootstrap(self.records)
        self.coordinator = RefreshCoordinator(
            self.auth_store, self.service, self.clock, RedactingFilter(secrets)
        )
        self.harvest_dir = root / "harvest"

    def worker(self, organization: str) -> HarvestWorker:
        store = HarvestStore(self.harvest_dir / f"{organization}.sqlite")
        return HarvestWorker(
            organization,
            self.coordinator,
            self.data_api,
            store,
            self.clock,
            sleep=lambda _s: None,
        )

    def cleanup(self) -> None:
        self.tmp.cleanup()


class PaginationDedupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = HarvestHarness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_full_harvest_then_resume_without_duplicates(self) -> None:
        report = self.h.worker("cooperative-a").run()
        self.assertEqual(report.pages_fetched, 4)
        self.assertEqual(report.records_inserted, 12)

        store = HarvestStore(self.h.harvest_dir / "cooperative-a.sqlite")
        self.assertEqual(
            store.counts(), {"pages_completed": 4, "records": 12}
        )
        store.close()

        # 重新运行：全部命中台账，零请求、零新增
        rerun = self.h.worker("cooperative-a").run()
        self.assertEqual(rerun.requests_made, 0)
        self.assertEqual(rerun.records_inserted, 0)
        self.assertEqual(rerun.pages_skipped_duplicate, 3)
        self.assertEqual(rerun.final_status, AuthStatus.ACTIVE.value)

    def test_duplicate_record_ids_are_ignored_even_without_page_journal(
        self,
    ) -> None:
        store = HarvestStore(self.h.harvest_dir / "cooperative-b.sqlite")
        now = self.h.clock.now()
        records = [{"id": "dup-1", "v": 1}, {"id": "dup-1", "v": 2}]
        first = store.insert_records(records, "cooperative-b:page:0", 2, now)
        second = store.insert_records(records, "cooperative-b:page:0", 2, now)
        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        store.close()

    def test_harvest_continues_after_token_rotation(self) -> None:
        # 先采集前两页，然后服务端轮换令牌；恢复后从断点继续且不重复
        store = HarvestStore(self.h.harvest_dir / "cooperative-a.sqlite")
        worker = HarvestWorker(
            "cooperative-a",
            self.h.coordinator,
            self.h.data_api,
            store,
            self.h.clock,
            sleep=lambda _s: None,
        )
        lease = self.h.coordinator.request_lease("cooperative-a")
        page0 = self.h.data_api.fetch_page(
            "cooperative-a", lease.access_token, None
        )
        store.insert_records(page0["records"], page0["page_key"], lease.fence,
                             self.h.clock.now())
        store.mark_page_completed(
            page0["page_key"], lease.fence, page0["next_cursor"],
            self.h.clock.now(),
        )

        self.h.service.force_access_expired("cooperative-a")
        report = worker.run()
        # 第 0 页已在台账中：worker 从台账游标直接续传，其余 3 页在新代次完成
        self.assertEqual(report.pages_fetched, 3)
        self.assertGreaterEqual(report.requests_made, 3)  # 含 401 重取，次数随调度变化
        self.assertEqual(store.counts()["records"], 12)
        self.assertEqual(store.counts()["pages_completed"], 4)
        store.close()


class SupervisorIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = HarvestHarness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_revoked_org_does_not_stop_other_org(self) -> None:
        self.h.coordinator.revoke("cooperative-b")
        supervisor = Supervisor(
            self.h.coordinator,
            self.h.data_api,
            str(self.h.harvest_dir),
            self.h.clock,
            sleep=lambda _s: None,
        )
        reports = supervisor.start(
            ["cooperative-a", "cooperative-b"]
        )
        self.assertEqual(
            reports["cooperative-b"].final_status, AuthStatus.REVOKED.value
        )
        self.assertEqual(
            reports["cooperative-a"].final_status, AuthStatus.ACTIVE.value
        )
        self.assertEqual(reports["cooperative-a"].records_inserted, 12)

    def test_pause_preserves_cursor_and_resume_completes(self) -> None:
        # 先完成两页
        store = HarvestStore(self.h.harvest_dir / "cooperative-a.sqlite")
        lease = self.h.coordinator.request_lease("cooperative-a")
        cursor = None
        for _ in range(2):
            page = self.h.data_api.fetch_page(
                "cooperative-a", lease.access_token, cursor
            )
            store.insert_records(page["records"], page["page_key"], lease.fence,
                                 self.h.clock.now())
            store.mark_page_completed(
                page["page_key"], lease.fence, page["next_cursor"],
                self.h.clock.now(),
            )
            cursor = page["next_cursor"]
        store.close()

        self.h.coordinator.set_paused("cooperative-a", True)
        paused = self.h.worker("cooperative-a").run()
        self.assertEqual(paused.records_inserted, 0)
        self.assertIsNotNone(paused.stopped_reason)

        self.h.coordinator.set_paused("cooperative-a", False)
        resumed = self.h.worker("cooperative-a").run()
        self.assertEqual(resumed.final_status, AuthStatus.ACTIVE.value)

        final_store = HarvestStore(
            self.h.harvest_dir / "cooperative-a.sqlite"
        )
        self.assertEqual(final_store.counts()["records"], 12)
        final_store.close()


class NoSecretLeakTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = HarvestHarness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_reports_and_errors_contain_no_plaintext_tokens(self) -> None:
        self.h.coordinator.revoke("cooperative-b")
        supervisor = Supervisor(
            self.h.coordinator,
            self.h.data_api,
            str(self.h.harvest_dir),
            self.h.clock,
            sleep=lambda _s: None,
        )
        reports = supervisor.start(["cooperative-a", "cooperative-b"])
        surface = json.dumps(
            [r.as_dict() for r in reports.values()]
            + self.h.coordinator.status(),
            ensure_ascii=False,
        )
        for record in self.h.records.values():
            self.assertNotIn(record.access_token.reveal(), surface)
            self.assertNotIn(record.refresh_token.reveal(), surface)


if __name__ == "__main__":
    unittest.main()
