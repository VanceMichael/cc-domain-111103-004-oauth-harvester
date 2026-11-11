"""秘密值包装与日志脱敏。

所有 access token / refresh token 在进程内都以 :class:`Secret` 承载。
Secret 不参与普通字符串拼接，``str()``/``repr()`` 只暴露指纹，
:class:`RedactingFilter` 保证即便有代码意外把秘密写进日志也会被抹除。
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable


class Secret:
    """一段不允许进入日志、异常消息或任务结果的敏感字符串。"""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise ValueError("秘密值必须是非空字符串")
        object.__setattr__(self, "_value", value)

    def reveal(self) -> str:
        """仅在真正需要发送给授权服务器/数据接口的调用边界使用。"""
        return self._value

    def fingerprint(self) -> str:
        """不可逆短指纹，用于在报告里区分两个令牌而不泄露内容。"""
        digest = hashlib.sha256(self._value.encode("utf-8")).hexdigest()
        return "tok-" + digest[:10]

    def __str__(self) -> str:  # 防止 print / f-string 意外泄密
        return f"Secret({self.fingerprint()})"

    def __repr__(self) -> str:
        return f"Secret({self.fingerprint()})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)


def redact(text: str, secrets: Iterable[Secret] | None = None) -> str:
    """把已知秘密值从文本中抹除（用于异常消息、任务结果的兜底处理）。"""
    if not isinstance(text, str):
        text = str(text)
    scrubbed = text
    for secret in secrets or ():
        scrubbed = scrubbed.replace(secret.reveal(), "***REDACTED***")
    return scrubbed


class RedactingFilter(logging.Filter):
    """日志过滤器：对登记过的所有秘密值做脱敏。"""

    def __init__(self, secrets: Iterable[Secret] | None = None) -> None:
        super().__init__()
        self._secrets: list[Secret] = list(secrets or ())

    def register(self, secret: Secret) -> None:
        self._secrets.append(secret)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for secret in self._secrets:
            message = message.replace(secret.reveal(), "***REDACTED***")
        record.msg = message
        record.args = ()
        return True
