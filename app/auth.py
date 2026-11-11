"""授权领域错误与状态定义。

所有异常消息只允许包含组织标识、状态码等非敏感信息，
禁止携带 access token / refresh token 明文。
"""

from __future__ import annotations

import enum


class AuthStatus(str, enum.Enum):
    """组织授权生命周期状态。"""

    ACTIVE = "active"
    """凭据有效，可正常采集。"""

    REFRESH_PENDING = "refresh_pending"
    """已发起刷新、结果尚未确认。期间旧 worker 不得再发请求。"""

    REAUTH_REQUIRED = "reauth_required"
    """refresh token 已失效或换发结果无法恢复，需要操作者重新授权。"""

    REVOKED = "revoked"
    """操作者已撤回授权，该组织停止一切访问。"""


class AuthError(Exception):
    """授权相关错误的基类，消息中不得包含秘密。"""


class AuthorizationRevoked(AuthError):
    def __init__(self, organization: str) -> None:
        super().__init__(f"组织 {organization} 的授权已被撤回")
        self.organization = organization


class AuthorizationPaused(AuthError):
    def __init__(self, organization: str) -> None:
        super().__init__(f"组织 {organization} 的采集已被操作者暂停")
        self.organization = organization


class ReauthorizationRequired(AuthError):
    def __init__(self, organization: str, reason: str) -> None:
        super().__init__(f"组织 {organization} 需要重新授权：{reason}")
        self.organization = organization
        self.reason = reason


class RefreshBusy(AuthError):
    """同一授权已有刷新过程在进行（单飞约束）。"""

    def __init__(self, organization: str) -> None:
        super().__init__(f"组织 {organization} 已有刷新过程在进行")
        self.organization = organization


class InvalidGrantResponse(AuthError):
    """令牌服务返回的响应无法通过校验。"""


class ServiceError(Exception):
    """令牌/数据接口的非授权类错误（网络超时、5xx 等），消息不含秘密。"""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class UnauthorizedResponse(ServiceError):
    """数据接口返回 401；由 worker 触发刷新协调，而不是自行换令牌。"""

    def __init__(self, organization: str) -> None:
        super().__init__(f"组织 {organization} 的数据请求返回 401", retryable=True)
        self.organization = organization
