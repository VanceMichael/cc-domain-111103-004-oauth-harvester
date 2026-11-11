"""端到端演示：多组织令牌轮换采集的协调与恢复。

运行：python3 -m app.demo

四个场景（全部使用虚构组织与虚构凭据）：
  1. 服务端已轮换而客户端超时 —— 挂起刷新的幂等确认与分页续传；
  2. 两个 worker 同时遇 401 —— 单飞刷新，旧刷新结果不可能覆盖新令牌；
  3. 换发成功但写本地存储前“进程退出” —— 重启恢复不重用失效旧 token；
  4. 仅一个组织撤权 / refresh 失效 —— 逐组织隔离、暂停恢复与重新授权视图。

每次运行重建 runtime/demo 目录；演示只读取虚构数据，不向任何真实服务发请求。
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

from app.auth import AuthStatus, ServiceError
from app.coordinator import RefreshCoordinator
from app.harvester import Supervisor
from app.oauth import load_grant_records
from app.secrets import RedactingFilter
from app.storage import AuthStore, HarvestStore
from app.token_service import Clock, MockDataApi, MockTokenService

RUNTIME = Path("runtime/demo")
ORGS = ["cooperative-a", "cooperative-b"]


class ManualClock(Clock):
    def __init__(self, start: int = 1_800_000_000) -> None:
        self._now = start

    def now(self) -> int:
        return self._now

    def advance(self, seconds: int) -> None:
        self._now += seconds


class SimulatedProcessExit(Exception):
    """模拟“换发成功但写本地存储前进程退出”。"""


def _build_services(clock: Clock, log_filter: RedactingFilter):
    records = load_grant_records()
    service = MockTokenService(clock)
    service.seed(records)
    data_api = MockDataApi(clock).bind(service)
    return records, service, data_api


def _new_coordinator(
    auth_root: Path,
    records,
    service: MockTokenService,
    clock: Clock,
    log_filter: RedactingFilter,
) -> RefreshCoordinator:
    store = AuthStore(auth_root)
    store.bootstrap(records)
    return RefreshCoordinator(store, service, clock, log_filter)


def _print_header(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def _print_status(coordinator: RefreshCoordinator) -> None:
    print("\n[授权状态（脱敏视图）]")
    for row in coordinator.status():
        print(
            f"  - {row['organization']}: 状态={row['status']}, 暂停={row['paused']}, "
            f"代次={row['generation']}, access={row['access_token']}, "
            f"refresh={row['refresh_token']}"
        )
        print(f"      下一步动作: {row['next_action']}")


def _print_reports(reports: dict) -> None:
    print("\n[采集报告]")
    for org, report in reports.items():
        data = report.as_dict()
        print(
            f"  - {org}: 新页面={data['pages_fetched']}, "
            f"重复页面跳过={data['pages_skipped_duplicate']}, "
            f"新记录={data['records_inserted']}, 重复记录拦截={data['record_duplicates']}, "
            f"实际请求={data['requests_made']}, 终态={data['final_status']}"
        )
        print(f"      停止原因: {data['stopped_reason']}")
        for event in data["events"]:
            print(f"      · {event}")


def _collect_all_secrets(*auth_roots: Path) -> list[str]:
    secrets: list[str] = []
    for root in auth_roots:
        for path in root.glob("*.json"):
            payload = json.loads(path.read_text(encoding="utf-8"))
            secrets.append(payload["access_token"])
            secrets.append(payload["refresh_token"])
    return [s for s in secrets if "placeholder" not in s]


def _assert_no_leak(text: str, secrets: list[str], label: str) -> None:
    leaked = [s for s in secrets if s and s in text]
    if leaked:
        raise AssertionError(f"{label} 中发现秘密明文泄露：{len(leaked)} 处")
    print(f"  秘密泄漏扫描通过：{label} 中无任何令牌明文")


# ---------------------------------------------------------------------------
# 场景 1：服务端已轮换而客户端超时
# ---------------------------------------------------------------------------

def scenario_timeout(clock: ManualClock, log_filter: RedactingFilter) -> None:
    _print_header("场景 1：服务端已轮换而客户端超时（timeout_after_rotation）")
    root = RUNTIME / "s1-auth"
    records, service, data_api = _build_services(clock, log_filter)
    coordinator = _new_coordinator(root, records, service, clock, log_filter)
    harvest_dir = RUNTIME / "s1-harvest"

    # cooperative-b 的首次刷新注入“轮换后响应丢失”
    service.set_refresh_scenario("cooperative-b", "timeout_after_rotation")
    service.force_access_expired("cooperative-b")
    # cooperative-a 注入一次数据接口网络超时（与 401 难以区分的可重试错误）
    service.set_data_timeouts("cooperative-a", 1)

    supervisor = Supervisor(coordinator, data_api, str(harvest_dir), clock, sleep=lambda _s: None)
    reports = supervisor.start(ORGS)
    _print_reports(reports)
    _print_status(coordinator)

    print("\n[恢复动作] 对挂起刷新执行启动恢复（同一 attempt 幂等确认）")
    outcome = coordinator.recover_all()
    print(f"  恢复结果: {outcome}")

    # 恢复后重新采集：从台账断点继续，已落库页面不重复请求、记录不重复插入
    print("\n[恢复后二次采集] 验证分页续传与去重")
    supervisor2 = Supervisor(coordinator, data_api, str(harvest_dir), clock, sleep=lambda _s: None)
    reports2 = supervisor2.start(ORGS)
    _print_reports(reports2)

    b_store = HarvestStore(str(Path(harvest_dir) / "cooperative-b.sqlite"))
    print(f"  cooperative-b 台账计数: {b_store.counts()}")
    b_store.close()

    # 第三次运行：两组织全部命中台账，零请求、零新增，证明重复页面不重复落库
    print("\n[第三次运行] 全部页面已在台账中，验证零重复落库")
    supervisor3 = Supervisor(coordinator, data_api, str(harvest_dir), clock, sleep=lambda _s: None)
    reports3 = supervisor3.start(ORGS)
    _print_reports(reports3)
    for org in ORGS:
        assert reports3[org].records_inserted == 0, f"{org} 重复运行不应产生新记录"
        assert reports3[org].requests_made == 0, f"{org} 台账命中时不应再发请求"
        assert reports3[org].pages_skipped_duplicate >= 1
    _assert_no_leak(json.dumps([r.as_dict() for r in reports2.values()], ensure_ascii=False),
                    _collect_all_secrets(root), "采集报告")


# ---------------------------------------------------------------------------
# 场景 2：两个 worker 同时遇 401
# ---------------------------------------------------------------------------

def scenario_concurrent_401(clock: ManualClock, log_filter: RedactingFilter) -> None:
    _print_header("场景 2：两个 worker 同时遇 401 —— 单飞刷新")
    root = RUNTIME / "s2-auth"
    records, service, data_api = _build_services(clock, log_filter)
    coordinator = _new_coordinator(root, records, service, clock, log_filter)

    service.force_access_expired("cooperative-a")

    import threading

    # 屏障保证两个 worker 在同一时刻发出数据请求，确定性地同时撞上 401
    barrier = threading.Barrier(2)
    results = {}

    def worker(name: str) -> None:
        lease = coordinator.request_lease("cooperative-a")
        barrier.wait()  # 双方就绪后同时发请求，排除调度先后的干扰
        try:
            data_api.fetch_page("cooperative-a", lease.access_token, None)
        except ServiceError:
            new_lease = coordinator.refresh_on_unauthorized(lease)
            results[name] = new_lease.fence

    t1 = threading.Thread(target=worker, args=("worker-1",))
    t2 = threading.Thread(target=worker, args=("worker-2",))
    t1.start(); t2.start(); t1.join(); t2.join()

    refresh_attempts = [
        call for call in service.refresh_calls if call[0] == "cooperative-a"
    ]
    print(f"  两个 worker 拿到的新 fence: {results}")
    print(f"  刷新端点实际调用次数: {len(refresh_attempts)}（单飞期望为 1）")
    assert len(refresh_attempts) == 1, "并发 401 必须合并为一次刷新"
    assert results["worker-1"] == results["worker-2"]
    state = coordinator.status("cooperative-a")[0]
    print(f"  cooperative-a 最终代次: {state['generation']}，状态: {state['status']}")
    assert state["status"] == AuthStatus.ACTIVE.value

    # 旧 refresh token 已失效：若有代码绕过协调器重试，服务端会拒绝
    from app.auth import ReauthorizationRequired

    old_refresh = records["cooperative-a"].refresh_token
    rogue_error: Exception | None = None
    try:
        service.refresh("cooperative-a", old_refresh, "rogue-attempt")
        raise AssertionError("旧 refresh token 应当已失效")
    except ReauthorizationRequired as exc:
        rogue_error = exc
        print(f"  绕过协调器重试旧 refresh token 被拒绝: {exc}")
    _assert_no_leak(str(rogue_error), _collect_all_secrets(root), "异常消息")


# ---------------------------------------------------------------------------
# 场景 3：换发成功但写本地存储前进程退出
# ---------------------------------------------------------------------------

def scenario_crash_recovery(clock: ManualClock, log_filter: RedactingFilter) -> None:
    _print_header("场景 3：换发成功、写本地存储前进程退出 —— 重启恢复")
    root = RUNTIME / "s3-auth"
    records, service, data_api = _build_services(clock, log_filter)
    coordinator = _new_coordinator(root, records, service, clock, log_filter)

    def crash_hook(organization: str, attempt_id: str) -> None:
        # 服务端轮换已完成，本地还没写入新令牌 —— 模拟此刻进程退出
        raise SimulatedProcessExit(f"模拟进程退出（org={organization}）")

    service.crash_hook = crash_hook
    service.set_refresh_scenario("cooperative-a", "crash_after_rotation")

    lease = coordinator.request_lease("cooperative-a")
    try:
        coordinator.refresh_on_unauthorized(lease)
    except SimulatedProcessExit as exc:
        print(f"  刷新过程中进程退出: {exc}")

    pending = coordinator.status("cooperative-a")[0]
    print(f"  磁盘上的持久化状态: status={pending['status']}, "
          f"挂起 attempt={pending['pending_attempt']}, 待确认代次={pending['pending_generation']}")
    assert pending["status"] == AuthStatus.REFRESH_PENDING.value

    print("\n[重启] 新进程重建服务与协调器，执行 recover_all()")
    clock.advance(5)
    coordinator2 = _new_coordinator(root, records, service, clock, log_filter)
    outcome = coordinator2.recover_all()
    print(f"  恢复结果: {outcome}")
    recovered = coordinator2.status("cooperative-a")[0]
    print(f"  cooperative-a: 状态={recovered['status']}, 代次={recovered['generation']}, "
          f"新 access={recovered['access_token']}")
    assert recovered["status"] == AuthStatus.ACTIVE.value
    assert recovered["generation"] == records["cooperative-a"].generation + 1

    print("\n[反向验证] 服务端无法重放旧 attempt 时，转入重新授权而非重用旧 token")
    root_b = RUNTIME / "s3b-auth"
    service_b = MockTokenService(clock)
    service_b.seed(records)
    service_b.set_refresh_scenario("cooperative-b", "crash_after_rotation")
    service_b.crash_hook = crash_hook
    coordinator_b = _new_coordinator(root_b, records, service_b, clock, log_filter)
    lease_b = coordinator_b.request_lease("cooperative-b")
    try:
        coordinator_b.refresh_on_unauthorized(lease_b)
    except SimulatedProcessExit:
        pass
    service_b.disable_replay("cooperative-b")
    try:
        coordinator_b.recover_pending_refresh("cooperative-b")
    except Exception as exc:  # noqa: BLE001
        print(f"  恢复被拒绝: {exc}")
    row = coordinator_b.status("cooperative-b")[0]
    print(f"  cooperative-b: 状态={row['status']}")
    print(f"      下一步动作: {row['next_action']}")
    assert row["status"] == AuthStatus.REAUTH_REQUIRED.value

    print("\n[操作者重新授权] 登记新令牌后恢复 ACTIVE 并继续采集")
    coordinator_b.reauthorize("cooperative-b")
    data_api_b = MockDataApi(clock).bind(service_b)  # 与 service_b 同一授权域
    harvest_dir = RUNTIME / "s3-harvest"
    supervisor = Supervisor(coordinator_b, data_api_b, str(harvest_dir), clock,
                            sleep=lambda _s: None)
    reports = supervisor.start(["cooperative-b"])
    _print_reports(reports)
    assert reports["cooperative-b"].final_status == AuthStatus.ACTIVE.value
    _assert_no_leak(json.dumps([r.as_dict() for r in reports.values()], ensure_ascii=False),
                    _collect_all_secrets(root, root_b), "采集报告")


# ---------------------------------------------------------------------------
# 场景 4：仅一个组织撤权 / refresh 失效；暂停与恢复
# ---------------------------------------------------------------------------

def scenario_revocation(clock: ManualClock, log_filter: RedactingFilter) -> None:
    _print_header("场景 4：单组织撤权与 refresh 失效 —— 逐组织隔离")
    root = RUNTIME / "s4-auth"
    records, service, data_api = _build_services(clock, log_filter)
    coordinator = _new_coordinator(root, records, service, clock, log_filter)
    harvest_dir = RUNTIME / "s4-harvest"

    print("\n[操作者撤回 cooperative-b 的授权]")
    coordinator.revoke("cooperative-b")
    _print_status(coordinator)

    supervisor = Supervisor(coordinator, data_api, str(harvest_dir), clock,
                            sleep=lambda _s: None)
    reports = supervisor.start(ORGS)
    _print_reports(reports)
    assert reports["cooperative-b"].final_status == AuthStatus.REVOKED.value
    assert reports["cooperative-a"].final_status == AuthStatus.ACTIVE.value
    a_store = HarvestStore(str(Path(harvest_dir) / "cooperative-a.sqlite"))
    print(f"  cooperative-a 未受影响，台账计数: {a_store.counts()}")
    a_store.close()

    print("\n[暂停 cooperative-a 后再恢复]")
    coordinator.set_paused("cooperative-a", True)
    paused_run = supervisor.start(["cooperative-a"])
    print(f"  暂停期间: {paused_run['cooperative-a'].stopped_reason}")
    assert paused_run["cooperative-a"].final_status == AuthStatus.ACTIVE.value
    coordinator.set_paused("cooperative-a", False)
    resumed_run = supervisor.start(["cooperative-a"])
    print(f"  恢复后: {resumed_run['cooperative-a'].stopped_reason}")

    print("\n[cooperative-b 重新完成授权]")
    coordinator.reauthorize("cooperative-b")
    rerun = supervisor.start(["cooperative-b"])
    _print_reports(rerun)

    print("\n[refresh token 单独失效（未撤权）]")
    service.rotate_manually("cooperative-a")  # 服务端带外轮换，客户端两令牌全失效
    stale_lease = coordinator.request_lease("cooperative-a")
    try:
        coordinator.refresh_on_unauthorized(stale_lease)
    except Exception as exc:  # noqa: BLE001
        print(f"  刷新被拒绝: {exc}")
    row = coordinator.status("cooperative-a")[0]
    print(f"  cooperative-a: 状态={row['status']}；下一步: {row['next_action']}")
    assert row["status"] == AuthStatus.REAUTH_REQUIRED.value

    _print_status(coordinator)
    leak_surface = json.dumps(
        [r.as_dict() for r in reports.values()]
        + [r.as_dict() for r in rerun.values()]
        + coordinator.status(),
        ensure_ascii=False,
    )
    _assert_no_leak(leak_surface, _collect_all_secrets(root), "任务结果与状态视图")


def main() -> None:
    if RUNTIME.exists():
        shutil.rmtree(RUNTIME)
    RUNTIME.mkdir(parents=True)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    log_filter = RedactingFilter()
    handler.addFilter(log_filter)
    logger.addHandler(handler)

    clock = ManualClock()
    scenario_timeout(clock, log_filter)
    scenario_concurrent_401(clock, log_filter)
    scenario_crash_recovery(clock, log_filter)
    scenario_revocation(clock, log_filter)

    _print_header("全部场景完成")
    print("runtime/demo 下保存各场景的授权状态（0600）与采集台账（0600），可离线核查。")


if __name__ == "__main__":
    main()
