"""采集 worker 与逐组织监督器。

worker 不持有任何刷新逻辑：每次请求前向 :class:`RefreshCoordinator` 取租约，
遇到 401 只调用协调器的单飞入口；刷新未确认期间租约不可得，自然无法发请求。
每个组织独立线程、独立台账，单个组织撤权/失效不会拖停其他组织。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from app.auth import (
    AuthStatus,
    AuthorizationPaused,
    AuthorizationRevoked,
    ReauthorizationRequired,
    ServiceError,
)
from app.coordinator import Lease, RefreshCoordinator
from app.storage import HarvestStore
from app.token_service import Clock, MockDataApi

logger = logging.getLogger("app.harvester")


@dataclass
class HarvestReport:
    organization: str
    pages_fetched: int = 0
    pages_skipped_duplicate: int = 0
    records_inserted: int = 0
    record_duplicates: int = 0
    requests_made: int = 0
    final_status: str = "active"
    stopped_reason: str | None = None
    events: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "organization": self.organization,
            "pages_fetched": self.pages_fetched,
            "pages_skipped_duplicate": self.pages_skipped_duplicate,
            "records_inserted": self.records_inserted,
            "record_duplicates": self.record_duplicates,
            "requests_made": self.requests_made,
            "final_status": self.final_status,
            "stopped_reason": self.stopped_reason,
            "events": list(self.events),
        }


class HarvestWorker:
    def __init__(
        self,
        organization: str,
        coordinator: RefreshCoordinator,
        data_api: MockDataApi,
        harvest_store: HarvestStore,
        clock: Clock,
        *,
        max_retries: int = 3,
        sleep: callable = time.sleep,
    ) -> None:
        self.organization = organization
        self._coordinator = coordinator
        self._api = data_api
        self._store = harvest_store
        self._clock = clock
        self._max_retries = max_retries
        self._sleep = sleep
        self.report = HarvestReport(organization)

    def run(self) -> HarvestReport:
        cursor = self._store.last_cursor()  # 换令牌/重启后从断点继续分页
        report = self.report
        while True:
            try:
                lease = self._coordinator.request_lease(self.organization)
            except AuthorizationRevoked:
                return self._stop(AuthStatus.REVOKED.value, "授权已撤回")
            except AuthorizationPaused:
                return self._stop(
                    self._coordinator.status(self.organization)[0]["status"],
                    "操作者已暂停，保留分页断点",
                )
            except ReauthorizationRequired as exc:
                self._coordinator.mark_reauth_required(self.organization, exc.reason)
                return self._stop(AuthStatus.REAUTH_REQUIRED.value, str(exc))

            page_key = f"{self.organization}:page:{0 if cursor is None else cursor}"
            if self._store.is_page_done(page_key):
                # 重复页面：台账拦截，不会再次请求，更不会重复落库。
                # 已完成页面的 next_cursor 在台账中，直接取它续传，避免游标回绕。
                report.pages_skipped_duplicate += 1
                report.events.append(f"跳过已完成页面 {page_key}")
                next_cursor = self._store.next_cursor_for(page_key)
                if next_cursor is None:
                    return self._stop(
                        self._coordinator.status(self.organization)[0]["status"],
                        "所有页面采集完成（重复运行，全部命中台账）",
                    )
                cursor = next_cursor
                continue

            try:
                response = self._fetch_with_retry(lease, cursor)
            except AuthorizationRevoked:
                return self._stop(AuthStatus.REVOKED.value, "授权已撤回")
            except AuthorizationPaused:
                return self._stop(
                    self._coordinator.status(self.organization)[0]["status"],
                    "刷新期间授权被暂停，保留分页断点",
                )
            except ReauthorizationRequired as exc:
                self._coordinator.mark_reauth_required(self.organization, exc.reason)
                return self._stop(AuthStatus.REAUTH_REQUIRED.value, str(exc))
            except ServiceError as exc:
                return self._stop("error", f"重试耗尽：{exc}")

            # 落库前再次校验 fence：期间若发生刷新，本页结果丢弃并重取
            if not self._coordinator.check_fence(lease):
                report.events.append(
                    f"页面 {page_key} 返回时代次已变化，丢弃结果并以新租约重取"
                )
                continue

            now = self._clock.now()
            inserted = self._store.insert_records(
                response["records"], page_key, lease.fence, now
            )
            report.record_duplicates += len(response["records"]) - inserted
            report.records_inserted += inserted
            self._store.mark_page_completed(
                page_key, lease.fence, response["next_cursor"], now
            )
            report.pages_fetched += 1
            report.events.append(
                f"完成页面 {page_key}（新记录 {inserted} 条，代次 {lease.fence}）"
            )

            cursor = response["next_cursor"]
            if cursor is None:
                return self._stop(
                    self._coordinator.status(self.organization)[0]["status"],
                    "所有页面采集完成",
                )

    def _fetch_with_retry(self, lease: Lease, cursor: str | None) -> dict:
        attempt = 0
        refresh_cycles = 0
        max_refresh_cycles = 2  # 同一页面最多触发两次刷新，防止 401↔刷新空转
        seen_fences: set[int] = set()
        while True:
            try:
                self.report.requests_made += 1
                return self._api.fetch_page(self.organization, lease.access_token, cursor)
            except ServiceError as exc:
                from app.auth import UnauthorizedResponse

                if isinstance(exc, UnauthorizedResponse):
                    # 唯一的刷新入口：交给协调器单飞处理，worker 自己绝不换令牌
                    if lease.fence in seen_fences or refresh_cycles >= max_refresh_cycles:
                        raise ReauthorizationRequired(
                            self.organization,
                            "令牌刷新后数据接口仍持续返回 401，停止自动重试",
                        )
                    seen_fences.add(lease.fence)
                    refresh_cycles += 1
                    lease = self._coordinator.refresh_on_unauthorized(lease)
                    self.report.events.append(
                        f"页面请求遇 401，已由协调器刷新到代次 {lease.fence}"
                    )
                    attempt = 0
                    continue
                attempt += 1
                if attempt > self._max_retries:
                    raise
                self.report.events.append(f"可重试错误（第 {attempt} 次）：{exc}")
                self._sleep(0)  # 测试中注入空转 sleep

    def _stop(self, status: str, reason: str) -> HarvestReport:
        self.report.final_status = status
        self.report.stopped_reason = reason
        self.report.events.append(f"停止：{reason}")
        logger.info("组织 %s 采集结束：%s", self.organization, reason)
        return self.report


class Supervisor:
    """每个组织一个独立线程，组织间故障互不影响。"""

    def __init__(
        self,
        coordinator: RefreshCoordinator,
        data_api: MockDataApi,
        harvest_dir: str,
        clock: Clock,
        **worker_kwargs,
    ) -> None:
        self._coordinator = coordinator
        self._data_api = data_api
        self._harvest_dir = harvest_dir
        self._clock = clock
        self._worker_kwargs = worker_kwargs
        self._threads: dict[str, threading.Thread] = {}
        self._reports: dict[str, HarvestReport] = {}

    def start(self, organizations: list[str]) -> dict[str, HarvestReport]:
        import threading

        for organization in organizations:
            thread = threading.Thread(
                target=self._run_one, args=(organization,), name=f"harvest-{organization}"
            )
            self._threads[organization] = thread
            thread.start()
        for thread in self._threads.values():
            thread.join()
        return dict(self._reports)

    def _run_one(self, organization: str) -> None:
        store = HarvestStore(f"{self._harvest_dir}/{organization}.sqlite")
        worker = HarvestWorker(
            organization,
            self._coordinator,
            self._data_api,
            store,
            self._clock,
            **self._worker_kwargs,
        )
        try:
            self._reports[organization] = worker.run()
        except Exception as exc:  # noqa: BLE001 - 隔离：单组织异常不拖停其他组织
            report = HarvestReport(
                organization, final_status="error", stopped_reason=str(exc)
            )
            self._reports[organization] = report
            logger.exception("组织 %s 采集异常被隔离", organization)
        finally:
            store.close()
