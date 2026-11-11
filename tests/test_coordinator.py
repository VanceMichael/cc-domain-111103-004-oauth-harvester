"""刷新协调、持久化代次与逐组织状态机的单元测试。"""

from __future__ import annotations

import json
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.auth import (
    AuthStatus,
    AuthorizationPaused,
    AuthorizationRevoked,
    ReauthorizationRequired,
    ServiceError,
    UnauthorizedResponse,
)
from app.coordinator import RefreshCoordinator
from app.oauth import load_grant_records
from app.secrets import RedactingFilter, Secret
from app.storage import AuthStore, PendingRefresh
from app.token_service import MockDataApi, MockTokenService


class FixedClock:
    def __init__(self, start: int = 1_800_000_000) -> None:
        self.value = start

    def now(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += seconds


class Harness:
    def __init__(self) -> None:
        self.tmp = TemporaryDirectory()
        root = Path(self.tmp.name)
        self.clock = FixedClock()
        self.records = load_grant_records()
        self.service = MockTokenService(self.clock)
        self.service.seed(self.records)
        self.data_api = MockDataApi(self.clock).bind(self.service)
        self.log_filter = RedactingFilter(
            [s for r in self.records.values() for s in (r.access_token, r.refresh_token)]
        )
        self.store = AuthStore(root / "auth")
        self.store.bootstrap(self.records)
        self.coordinator = RefreshCoordinator(
            self.store, self.service, self.clock, self.log_filter
        )
        self.harvest_dir = root / "harvest"

    def cleanup(self) -> None:
        self.tmp.cleanup()


class SecretTests(unittest.TestCase):
    def test_secret_never_renders_plaintext(self) -> None:
        secret = Secret("super-secret-value")
        self.assertNotIn("super-secret-value", str(secret))
        self.assertNotIn("super-secret-value", repr(secret))
        self.assertEqual(secret.reveal(), "super-secret-value")

    def test_redacting_filter_scrubs_logs(self) -> None:
        import logging

        secret = Secret("super-secret-value")
        log_filter = RedactingFilter([secret])
        record = logging.LogRecord(
            "x", logging.INFO, "", 0, "token=%s", (secret.reveal(),), None
        )
        log_filter.filter(record)
        self.assertNotIn("super-secret-value", record.getMessage())
        self.assertIn("***REDACTED***", record.getMessage())


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_auth_file_permissions_and_atomic_layout(self) -> None:
        for org in self.h.store.all_orgs():
            path = self.h.store._path(org)
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
            self.assertFalse(path.with_name(path.name + ".tmp").exists())

    def test_pending_refresh_persisted_before_network(self) -> None:
        lease = self.h.coordinator.request_lease("cooperative-b")
        self.h.service.set_refresh_scenario(
            "cooperative-b", "timeout_after_rotation"
        )
        with self.assertRaises(ServiceError):
            self.h.coordinator.refresh_on_unauthorized(lease)
        on_disk = json.loads(
            self.h.store._path("cooperative-b").read_text(encoding="utf-8")
        )
        self.assertEqual(on_disk["status"], AuthStatus.REFRESH_PENDING.value)
        self.assertIsNotNone(on_disk["pending"]["attempt_id"])
        # 磁盘文件只存该组织自己的记录
        self.assertEqual(on_disk["organization"], "cooperative-b")

    def test_redacted_snapshot_contains_no_plaintext_secret(self) -> None:
        snapshot = json.dumps(self.h.store.redacted_snapshot(), ensure_ascii=False)
        for record in self.h.records.values():
            self.assertNotIn(record.access_token.reveal(), snapshot)
            self.assertNotIn(record.refresh_token.reveal(), snapshot)


class SingleFlightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_concurrent_401_triggers_single_refresh(self) -> None:
        self.h.service.force_access_expired("cooperative-a")
        barrier = threading.Barrier(2)
        fences: dict[str, int] = {}

        def worker(name: str) -> None:
            lease = self.h.coordinator.request_lease("cooperative-a")
            barrier.wait()
            try:
                self.h.data_api.fetch_page(
                    "cooperative-a", lease.access_token, None
                )
            except UnauthorizedResponse:
                fences[name] = self.h.coordinator.refresh_on_unauthorized(
                    lease
                ).fence

        threads = [threading.Thread(target=worker, args=(n,)) for n in ("w1", "w2")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        refresh_calls = [
            c for c in self.h.service.refresh_calls if c[0] == "cooperative-a"
        ]
        self.assertEqual(len(refresh_calls), 1)
        self.assertEqual(set(fences.values()), {5})
        self.assertEqual(
            self.h.store.load("cooperative-a").status, AuthStatus.ACTIVE
        )

    def test_old_refresh_token_rejected_after_rotation(self) -> None:
        old_refresh = self.h.records["cooperative-a"].refresh_token
        lease = self.h.coordinator.request_lease("cooperative-a")
        self.h.service.force_access_expired("cooperative-a")
        with self.assertRaises(UnauthorizedResponse):
            self.h.data_api.fetch_page("cooperative-a", lease.access_token, None)
        self.h.coordinator.refresh_on_unauthorized(lease)
        with self.assertRaises(ReauthorizationRequired):
            self.h.service.refresh("cooperative-a", old_refresh, "rogue")


class FenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_lease_blocked_while_refresh_pending(self) -> None:
        # 先让服务端真实完成一次轮换（模拟换发成功、本地写盘前崩溃），
        # 再手动构造与服务端 attempt 对应的持久化 refresh_pending 现场
        state = self.h.store.load("cooperative-a")
        attempt_id = "pending-attempt"
        tokens = self.h.service.refresh(
            "cooperative-a", state.refresh_token, attempt_id
        )
        state.status = AuthStatus.REFRESH_PENDING
        state.pending = PendingRefresh(
            attempt_id=attempt_id,
            expected_generation=tokens.generation,
            started_at=self.h.clock.now(),
            refresh_fingerprint=state.refresh_token.fingerprint(),
        )
        self.h.store.save(state)

        lease_result: list[int] = []
        done = threading.Event()

        def waiter() -> None:
            lease_result.append(
                self.h.coordinator.request_lease("cooperative-a").fence
            )
            done.set()

        thread = threading.Thread(target=waiter)
        thread.start()
        # 挂起期间旧 worker 拿不到租约，线程必须等待而不是返回
        self.assertFalse(done.wait(timeout=0.5))

        # 恢复确认挂起 attempt 后，等待者被唤醒并拿到新代次租约
        self.h.coordinator.recover_pending_refresh("cooperative-a")
        self.assertTrue(done.wait(timeout=5))
        thread.join(timeout=5)
        self.assertEqual(lease_result, [5])

    def test_check_fence_invalidates_stale_lease(self) -> None:
        lease = self.h.coordinator.request_lease("cooperative-a")
        self.h.service.force_access_expired("cooperative-a")
        with self.assertRaises(UnauthorizedResponse):
            self.h.data_api.fetch_page("cooperative-a", lease.access_token, None)
        self.h.coordinator.refresh_on_unauthorized(lease)
        self.assertFalse(self.h.coordinator.check_fence(lease))


class RecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_crash_before_local_write_recovers_via_attempt_replay(self) -> None:
        def crash_hook(*_args) -> None:
            raise RuntimeError("simulated process exit")

        self.h.service.crash_hook = crash_hook
        self.h.service.set_refresh_scenario(
            "cooperative-a", "crash_after_rotation"
        )
        lease = self.h.coordinator.request_lease("cooperative-a")
        with self.assertRaises(RuntimeError):
            self.h.coordinator.refresh_on_unauthorized(lease)

        # 模拟新进程：重建协调器，磁盘状态保留挂起 attempt
        coordinator2 = RefreshCoordinator(
            self.h.store, self.h.service, self.h.clock, self.h.log_filter
        )
        state = coordinator2.recover_pending_refresh("cooperative-a")
        self.assertEqual(state.status, AuthStatus.ACTIVE)
        self.assertEqual(state.generation, 5)

    def test_recovery_without_replay_goes_to_reauth_not_old_token(self) -> None:
        def crash_hook(*_args) -> None:
            raise RuntimeError("simulated process exit")

        self.h.service.crash_hook = crash_hook
        self.h.service.set_refresh_scenario(
            "cooperative-b", "crash_after_rotation"
        )
        lease = self.h.coordinator.request_lease("cooperative-b")
        with self.assertRaises(RuntimeError):
            self.h.coordinator.refresh_on_unauthorized(lease)

        self.h.service.disable_replay("cooperative-b")
        coordinator2 = RefreshCoordinator(
            self.h.store, self.h.service, self.h.clock, self.h.log_filter
        )
        with self.assertRaises(ReauthorizationRequired):
            coordinator2.recover_pending_refresh("cooperative-b")
        state = self.h.store.load("cooperative-b")
        self.assertEqual(state.status, AuthStatus.REAUTH_REQUIRED)
        # 旧 refresh token 原样保留但永不再被自动使用
        self.assertEqual(
            state.refresh_token, self.h.records["cooperative-b"].refresh_token
        )


class PauseRevokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_pause_blocks_lease_and_resume_restores(self) -> None:
        self.h.coordinator.set_paused("cooperative-a", True)
        with self.assertRaises(AuthorizationPaused):
            self.h.coordinator.request_lease("cooperative-a")
        self.h.coordinator.set_paused("cooperative-a", False)
        lease = self.h.coordinator.request_lease("cooperative-a")
        self.assertEqual(lease.fence, 4)

    def test_revoke_clears_local_secret_and_blocks(self) -> None:
        self.h.coordinator.revoke("cooperative-b")
        with self.assertRaises(AuthorizationRevoked):
            self.h.coordinator.request_lease("cooperative-b")
        on_disk = json.loads(
            self.h.store._path("cooperative-b").read_text(encoding="utf-8")
        )
        self.assertNotIn(
            self.h.records["cooperative-b"].access_token.reveal(),
            json.dumps(on_disk),
        )
        # 另一组织完全不受影响
        self.assertEqual(
            self.h.store.load("cooperative-a").status, AuthStatus.ACTIVE
        )

    def test_reauthorize_returns_to_active(self) -> None:
        self.h.coordinator.revoke("cooperative-b")
        state = self.h.coordinator.reauthorize("cooperative-b")
        self.assertEqual(state.status, AuthStatus.ACTIVE)
        lease = self.h.coordinator.request_lease("cooperative-b")
        self.assertEqual(lease.fence, state.generation)


class IsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.h = Harness()

    def tearDown(self) -> None:
        self.h.cleanup()

    def test_one_org_failure_does_not_touch_other_org_file(self) -> None:
        before = self.h.store._path("cooperative-a").read_bytes()
        self.h.coordinator.revoke("cooperative-b")
        after = self.h.store._path("cooperative-a").read_bytes()
        self.assertEqual(before, after)

    def test_one_org_reauth_does_not_block_other_org_lease(self) -> None:
        self.h.service.rotate_manually("cooperative-a")
        lease = self.h.coordinator.request_lease("cooperative-a")
        with self.assertRaises(ReauthorizationRequired):
            self.h.coordinator.refresh_on_unauthorized(lease)
        # cooperative-b 仍可正常取租约
        lease_b = self.h.coordinator.request_lease("cooperative-b")
        self.assertEqual(lease_b.fence, 2)


if __name__ == "__main__":
    unittest.main()
