"""本地令牌服务 / 数据接口替身。

替身模拟合作方只读授权服务的关键语义，全部数据虚构：

* 刷新端点成功轮换后，旧 refresh token 立即失效，旧 access token 同时作废；
* 同一 attempt_id 的刷新请求可幂等重放（模拟“服务端已轮换而客户端超时”
  以及“换发成功但写本地存储前进程退出”的恢复路径）；
* 可注入逐组织撤权、仅一次/持续超时、进程退出钩子等故障；
* 组织之间完全隔离：一个组织被撤权或 refresh 失效不影响其他组织。
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass

from app.auth import (
    InvalidGrantResponse,
    ReauthorizationRequired,
    ServiceError,
    UnauthorizedResponse,
)
from app.oauth import GrantRecord
from app.secrets import Secret


class Clock:
    """可注入的时钟，测试与演示中用虚拟时钟驱动过期判断。"""

    def now(self) -> int:
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> int:
        return int(time.time())


@dataclass
class TokenSet:
    access_token: Secret
    refresh_token: Secret
    generation: int
    expires_at: int
    ttl_seconds: int


@dataclass
class _ServerState:
    access: Secret
    refresh: Secret
    generation: int
    revoked: bool = False
    next_scenario: str | None = None  # 下一次刷新注入的故障
    data_timeouts_left: int = 0  # 数据接口剩余超时次数
    replay_available: bool = True  # attempt 幂等重放是否仍可用
    previous_access: Secret | None = None  # 上一代次 access（刷新窗口在途请求）


class MockTokenService:
    """内存中的授权服务器替身，线程安全。"""

    def __init__(self, clock: Clock, access_ttl: int = 3600) -> None:
        self._clock = clock
        self._access_ttl = access_ttl
        self._states: dict[str, _ServerState] = {}
        self._rotations: dict[str, TokenSet] = {}  # attempt_id -> 已换发结果
        self._lock = threading.Lock()
        self.refresh_calls: list[tuple[str, str]] = []  # (org, attempt_id)
        # 崩溃钩子：刷新成功后、服务端返回前调用；钩子抛异常即模拟进程退出
        self.crash_hook: callable | None = None

    # -- 测试/演示装配 -----------------------------------------------------

    def seed(self, records: dict[str, GrantRecord]) -> None:
        for org, record in records.items():
            self._states[org] = _ServerState(
                access=record.access_token,
                refresh=record.refresh_token,
                generation=record.generation,
            )

    def set_refresh_scenario(self, organization: str, scenario: str) -> None:
        self._states[organization].next_scenario = scenario

    def set_data_timeouts(self, organization: str, count: int) -> None:
        self._states[organization].data_timeouts_left = count

    def disable_replay(self, organization: str) -> None:
        """模拟服务端无法再重放旧 attempt（恢复时只能要求重新授权）。"""
        self._states[organization].replay_available = False

    def force_access_expired(self, organization: str) -> None:
        """让当前 access token 立即失效（模拟服务端侧过期），触发 worker 401。"""
        with self._lock:
            self._states[organization].access = Secret("expired-" + uuid.uuid4().hex)

    def rotate_manually(self, organization: str) -> None:
        """模拟服务端侧独立轮换，使客户端持有的两个令牌全部失效。"""
        with self._lock:
            state = self._states[organization]
            state.generation += 1
            state.access = Secret(f"srv-access-{organization}-{state.generation}")
            state.refresh = Secret(f"srv-refresh-{organization}-{state.generation}")

    # -- 刷新端点 -----------------------------------------------------------

    def refresh(
        self, organization: str, refresh_token: Secret, attempt_id: str
    ) -> TokenSet:
        """执行一次令牌换发。

        并发安全：同一 attempt_id 的重复调用走幂等重放；
        使用已失效 refresh token 会得到 reauth_required 语义错误。
        """
        with self._lock:
            state = self._states.get(organization)
            if state is None:
                raise ReauthorizationRequired(organization, "服务端无此授权记录")
            self.refresh_calls.append((organization, attempt_id))

            # 1) 幂等重放：该 attempt 已在服务端完成过轮换
            if attempt_id in self._rotations:
                if not state.replay_available:
                    raise ReauthorizationRequired(
                        organization, "挂起的刷新 attempt 已无法在服务端重放"
                    )
                return self._rotations[attempt_id]

            # 2) 已撤权组织直接拒绝
            if state.revoked:
                raise ReauthorizationRequired(organization, "授权已被撤回")

            # 3) 旧 refresh token 已在先前轮换中失效
            if refresh_token != state.refresh:
                raise ReauthorizationRequired(
                    organization, "refresh token 已失效（可能已被先前轮换作废）"
                )

            scenario = state.next_scenario
            state.next_scenario = None

            # 4) 执行真正的轮换：旧 refresh / access 同时失效
            state.generation += 1
            new_set = TokenSet(
                access_token=Secret(f"synthetic-access-{organization}-{state.generation}"),
                refresh_token=Secret(
                    f"synthetic-refresh-{organization}-{state.generation}"
                ),
                generation=state.generation,
                expires_at=self._clock.now() + self._access_ttl,
                ttl_seconds=self._access_ttl,
            )
            self._rotations[attempt_id] = new_set
            state.previous_access = state.access  # 上一代次保留一个在途宽限窗口
            state.access = new_set.access_token
            state.refresh = new_set.refresh_token

            # 5) 故障注入：模拟“服务端已轮换、客户端却收不到响应”
            if scenario in ("timeout_after_rotation", "crash_after_rotation"):
                if self.crash_hook is not None and scenario == "crash_after_rotation":
                    self.crash_hook(organization, attempt_id)
                raise ServiceError(
                    f"组织 {organization} 的刷新请求在服务端轮换后超时（响应丢失）",
                    retryable=True,
                )
            if scenario == "unavailable":
                raise ServiceError(
                    f"组织 {organization} 的刷新端点暂不可用", retryable=True
                )
            if scenario is not None:
                raise InvalidGrantResponse(
                    f"组织 {organization} 的刷新响应包含未知场景：{scenario}"
                )
            return new_set

    def revoke(self, organization: str) -> None:
        with self._lock:
            self._states[organization].revoked = True
            self._states[organization].access = Secret(
                "revoked-" + uuid.uuid4().hex
            )

    def reauthorize(
        self, organization: str, generation: int, ttl_seconds: int | None = None
    ) -> TokenSet:
        """操作者引导重新授权后，服务端签发一套全新令牌。"""
        ttl = ttl_seconds or self._access_ttl
        with self._lock:
            state = self._states[organization]
            state.revoked = False
            state.replay_available = True
            state.generation = max(state.generation, generation) + 1
            tokens = TokenSet(
                access_token=Secret(f"reauth-access-{organization}-{state.generation}"),
                refresh_token=Secret(
                    f"reauth-refresh-{organization}-{state.generation}"
                ),
                generation=state.generation,
                expires_at=self._clock.now() + ttl,
                ttl_seconds=ttl,
            )
            state.access = tokens.access_token
            state.refresh = tokens.refresh_token
            return tokens

    def is_revoked(self, organization: str) -> bool:
        return self._states[organization].revoked


class MockDataApi:
    """内存中的只读数据接口替身，按页返回虚构记录。"""

    def __init__(self, clock: Clock, page_size: int = 3, total_pages: int = 4) -> None:
        self._clock = clock
        self._page_size = page_size
        self._total_pages = total_pages
        self._service: MockTokenService | None = None
        self.request_log: list[tuple[str, str]] = []  # (org, page_key)

    def bind(self, token_service: MockTokenService) -> "MockDataApi":
        self._service = token_service
        return self

    def fetch_page(
        self, organization: str, access_token: Secret, cursor: str | None
    ) -> dict:
        state = self._service._states[organization]  # 同进程替身，直接校验
        if state.data_timeouts_left > 0:
            state.data_timeouts_left -= 1
            raise ServiceError(
                f"组织 {organization} 的数据请求网络超时", retryable=True
            )
        if state.revoked:
            raise UnauthorizedResponse(organization)
        if access_token not in (state.access, state.previous_access):
            # 真正的 401：令牌完全不认识，或已超出一个轮换窗口的老代次。
            # 刷新瞬间仍在途的上一代次 token 允许到达业务层，
            # 但 worker 回到协调器做 fence 校验时会丢弃过期代次的结果并重取。
            raise UnauthorizedResponse(organization)

        page_index = 0 if cursor is None else int(cursor)
        page_key = f"{organization}:page:{page_index}"
        self.request_log.append((organization, page_key))

        start = page_index * self._page_size
        records = [
            {
                "id": f"{organization}-rec-{start + offset}",
                "organization": organization,
                "seq": start + offset,
            }
            for offset in range(self._page_size)
        ]
        next_cursor = (
            str(page_index + 1) if page_index + 1 < self._total_pages else None
        )
        return {
            "page_key": page_key,
            "records": records,
            "next_cursor": next_cursor,
        }
