"""刷新协调与逐组织授权状态机。

核心机制：

1. **单飞（single-flight）**：每个组织一把锁 + Condition。两个 worker 同时遇到
   401 时，只有一个真正调用刷新端点，另一个等待同一结果；旧刷新结果不可能
   覆盖新令牌，因为同代次只允许一个刷新过程。
2. **持久化代次与 fence**：租约携带 ``fence`` 代次。刷新一旦发起（先落盘
   ``refresh_pending`` 再出网），旧 fence 的 worker 立刻失效；刷新未确认期间
   任何请求都拿不到新租约，因此旧 worker 无法再发送请求。
3. **崩溃恢复**：换发成功但写本地存储前退出时，磁盘上保留 attempt id，
   重启后用同一 attempt id 做幂等确认，而不是重用已失效的旧 refresh token；
   服务端无法重放时转为“需要重新授权”，绝不拿旧 token 再试。
4. **逐组织隔离**：所有状态按组织保存与加锁，单组织撤权/失效只影响自己。
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass

from app.auth import (
    AuthStatus,
    AuthorizationPaused,
    AuthorizationRevoked,
    ReauthorizationRequired,
    RefreshBusy,
    ServiceError,
)
from app.secrets import RedactingFilter, Secret
from app.storage import AuthState, AuthStore, PendingRefresh
from app.token_service import Clock, MockTokenService, TokenSet

logger = logging.getLogger("app.coordinator")


@dataclass(frozen=True)
class Lease:
    """一次数据请求的入场凭证；fence 变化后旧租约立即作废。"""

    organization: str
    access_token: Secret
    fence: int


class _OrgGate:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.refreshing = False
        self.refresh_error: Exception | None = None


class RefreshCoordinator:
    def __init__(
        self,
        store: AuthStore,
        token_service: MockTokenService,
        clock: Clock,
        log_filter: RedactingFilter | None = None,
    ) -> None:
        self._store = store
        self._service = token_service
        self._clock = clock
        self._gates: dict[str, _OrgGate] = {}
        self._gates_lock = threading.Lock()
        self._log_filter = log_filter

    # -- 内部工具 -----------------------------------------------------------

    def _gate(self, organization: str) -> _OrgGate:
        with self._gates_lock:
            gate = self._gates.get(organization)
            if gate is None:
                gate = _OrgGate()
                self._gates[organization] = gate
            return gate

    def _register(self, *secrets: Secret) -> None:
        if self._log_filter is not None:
            for secret in secrets:
                self._log_filter.register(secret)

    def _fail_reauth(self, state: AuthState, reason: str) -> None:
        state.status = AuthStatus.REAUTH_REQUIRED
        state.reauth_reason = reason
        state.pending = None
        self._store.save(state)
        logger.warning("组织 %s 转入重新授权状态：%s", state.organization, reason)

    # -- 租约（fence） ------------------------------------------------------

    def request_lease(self, organization: str) -> Lease:
        """worker 每次发请求前必须获取当前租约；拿不到就不许发请求。"""
        gate = self._gate(organization)
        with gate.condition:
            while True:
                state = self._store.load(organization)
                if state.status is AuthStatus.REVOKED:
                    raise AuthorizationRevoked(organization)
                if state.paused:
                    raise AuthorizationPaused(organization)
                if state.status is AuthStatus.REAUTH_REQUIRED:
                    raise ReauthorizationRequired(
                        organization,
                        state.reauth_reason or "refresh token 已失效",
                    )
                if state.status is AuthStatus.REFRESH_PENDING:
                    # 新令牌尚未确认：旧 worker 在此等待，期间不能发出任何请求
                    gate.condition.wait_for(lambda: not gate.refreshing)
                    continue
                return Lease(organization, state.access_token, state.generation)

    def check_fence(self, lease: Lease) -> bool:
        """请求返回后校验租约是否仍为最新代次。"""
        state = self._store.load(lease.organization)
        return (
            state.status is AuthStatus.ACTIVE
            and not state.paused
            and state.generation == lease.fence
            and state.access_token == lease.access_token
        )

    # -- 刷新（单飞） -------------------------------------------------------

    def refresh_on_unauthorized(self, lease: Lease) -> Lease:
        """worker 遇到 401 后的唯一入口：不允许自行散落刷新逻辑。"""
        gate = self._gate(lease.organization)
        with gate.condition:
            state = self._store.load(lease.organization)
            if state.status is AuthStatus.REVOKED:
                raise AuthorizationRevoked(lease.organization)
            if state.paused:
                raise AuthorizationPaused(lease.organization)

            # 其他 worker 已完成刷新：本 worker 的 fence 已过期，直接领新租约，
            # 绝不允许再发起第二个刷新过程（旧刷新结果覆盖新令牌的根源即在此）。
            if state.status is AuthStatus.ACTIVE and state.generation != lease.fence:
                logger.info(
                    "组织 %s 的 401 已由另一刷新过程处理，fence %d -> %d",
                    lease.organization,
                    lease.fence,
                    state.generation,
                )
                return Lease(lease.organization, state.access_token, state.generation)

            # 已有同组织刷新在途：等待其结果，绝不发起第二个刷新过程
            if gate.refreshing or state.status is AuthStatus.REFRESH_PENDING:
                gate.condition.wait_for(lambda: not gate.refreshing)
                if gate.refresh_error is not None:
                    raise gate.refresh_error
                latest = self._store.load(lease.organization)
                return Lease(
                    latest.organization, latest.access_token, latest.generation
                )

            gate.refreshing = True
            gate.refresh_error = None
            try:
                new_state = self._do_refresh(state)
            except Exception as exc:  # noqa: BLE001 - 记录后广播给等待者
                gate.refresh_error = exc
                raise
            finally:
                gate.refreshing = False
                gate.condition.notify_all()
            return Lease(
                new_state.organization,
                new_state.access_token,
                new_state.generation,
            )

    def _do_refresh(self, state: AuthState) -> AuthState:
        """调用方已持有该组织 gate 锁。先持久化 pending，再出网换发。"""
        organization = state.organization
        attempt_id = uuid.uuid4().hex
        expected_generation = state.generation + 1

        # 关键顺序：pending 先落盘，旧 fence 随即失效，旧 worker 拿不到新租约
        state.status = AuthStatus.REFRESH_PENDING
        state.pending = PendingRefresh(
            attempt_id=attempt_id,
            expected_generation=expected_generation,
            started_at=self._clock.now(),
            refresh_fingerprint=state.refresh_token.fingerprint(),
        )
        self._store.save(state)
        logger.info(
            "组织 %s 发起刷新 attempt=%s 待确认代次=%d",
            organization,
            attempt_id,
            expected_generation,
        )

        try:
            tokens = self._service.refresh(
                organization, state.refresh_token, attempt_id
            )
        except ReauthorizationRequired as exc:
            self._fail_reauth(state, exc.reason)
            raise
        except ServiceError as exc:
            # 超时类错误：服务端可能已经轮换。挂起状态保留在磁盘上，
            # 由 recover_pending_refresh 走幂等确认，而不是在此重用旧 token。
            state.status = AuthStatus.REFRESH_PENDING
            self._store.save(state)
            logger.warning(
                "组织 %s 刷新未确认（%s），挂起 attempt=%s 等待恢复确认",
                organization,
                exc,
                attempt_id,
            )
            raise
        return self._commit_tokens(state, tokens)

    def _commit_tokens(self, state: AuthState, tokens: TokenSet) -> AuthState:
        if tokens.generation != (state.pending.expected_generation if state.pending
                                  else state.generation + 1):
            # 代次对不上说明发生了非预期的带外轮换，交回重新授权流程
            self._fail_reauth(state, "服务端返回的令牌代次与本地待确认代次不一致")
            raise ReauthorizationRequired(state.organization, "令牌代次不一致")
        state.access_token = tokens.access_token
        state.refresh_token = tokens.refresh_token
        state.generation = tokens.generation
        state.expires_at = tokens.expires_at
        state.status = AuthStatus.ACTIVE
        state.pending = None
        state.reauth_reason = None
        self._store.save(state)
        self._register(tokens.access_token, tokens.refresh_token)
        logger.info(
            "组织 %s 刷新已确认，新代次=%d", state.organization, tokens.generation
        )
        return state

    # -- 崩溃恢复 -----------------------------------------------------------

    def recover_pending_refresh(self, organization: str) -> AuthState | None:
        """进程启动时调用：确认上次退出前未写完的刷新。

        不重新发起刷新，只用磁盘上的 attempt id 做幂等重放；
        服务端无法重放或 refresh token 已失效时转入重新授权状态。
        """
        state = self._store.load(organization)
        if state.status is not AuthStatus.REFRESH_PENDING or state.pending is None:
            return state

        attempt = state.pending
        logger.info(
            "组织 %s 恢复挂起刷新 attempt=%s，执行幂等确认",
            organization,
            attempt.attempt_id,
        )
        try:
            tokens = self._service.refresh(
                organization, state.refresh_token, attempt.attempt_id
            )
        except ReauthorizationRequired as exc:
            self._fail_reauth(state, exc.reason)
            raise
        except ServiceError as exc:
            # 服务端仍不可用：保留挂起状态，下次启动继续确认，旧 token 不会被重用
            logger.warning("组织 %s 恢复确认仍未成功：%s", organization, exc)
            return state
        return self._commit_tokens(state, tokens)

    def recover_all(self) -> dict[str, str]:
        """启动恢复入口，返回每个组织恢复后的状态（脱敏值，可直接展示）。"""
        outcome: dict[str, str] = {}
        for organization in self._store.all_orgs():
            state = self._store.load(organization)
            if state.status is AuthStatus.REFRESH_PENDING:
                self.recover_pending_refresh(organization)
            outcome[organization] = self._store.load(organization).status.value
        return outcome

    def mark_reauth_required(self, organization: str, reason: str) -> None:
        """刷新后仍持续 401 等无法自愈的情况：显式转入重新授权状态。"""
        gate = self._gate(organization)
        with gate.condition:
            state = self._store.load(organization)
            if state.status in (AuthStatus.REVOKED, AuthStatus.REAUTH_REQUIRED):
                return
            self._fail_reauth(state, reason)
            gate.condition.notify_all()

    # -- 操作者动作：暂停 / 恢复 / 撤权 / 重新授权 ---------------------------

    def set_paused(self, organization: str, paused: bool) -> None:
        gate = self._gate(organization)
        with gate.condition:
            state = self._store.load(organization)
            if state.status is AuthStatus.REVOKED:
                raise AuthorizationRevoked(organization)
            state.paused = paused
            self._store.save(state)
            gate.condition.notify_all()
            logger.info("组织 %s 采集已%s", organization, "暂停" if paused else "恢复")

    def revoke(self, organization: str) -> None:
        """操作者撤回授权：本地清除秘密，服务端替身同步作废。"""
        gate = self._gate(organization)
        with gate.condition:
            state = self._store.load(organization)
            self._service.revoke(organization)
            state.status = AuthStatus.REVOKED
            state.paused = False
            state.pending = None
            state.reauth_reason = "操作者撤回授权"
            # 本地不再保留任何可用凭据；以不可用占位替换，避免残留秘密
            state.access_token = Secret("revoked-placeholder")
            state.refresh_token = Secret("revoked-placeholder")
            self._store.save(state)
            gate.condition.notify_all()
            logger.info("组织 %s 授权已撤回，本地凭据已清除", organization)

    def reauthorize(self, organization: str) -> AuthState:
        """操作者引导重新授权后登记新令牌，状态回到 ACTIVE。"""
        gate = self._gate(organization)
        with gate.condition:
            state = self._store.load(organization)
            if state.status not in (
                AuthStatus.REAUTH_REQUIRED,
                AuthStatus.REVOKED,
            ):
                raise RefreshBusy(organization)
            tokens = self._service.reauthorize(organization, state.generation)
            state.access_token = tokens.access_token
            state.refresh_token = tokens.refresh_token
            state.generation = tokens.generation
            state.expires_at = tokens.expires_at
            state.status = AuthStatus.ACTIVE
            state.paused = False
            state.pending = None
            state.reauth_reason = None
            self._store.save(state)
            self._register(tokens.access_token, tokens.refresh_token)
            gate.condition.notify_all()
            logger.info("组织 %s 已重新授权，代次=%d", organization, tokens.generation)
            return state

    # -- 操作者视图 ----------------------------------------------------------

    def status(self, organization: str | None = None) -> list[dict]:
        return self._store.redacted_snapshot(organization)
