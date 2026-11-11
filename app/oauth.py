"""授权来源材料读取（fixtures 为虚构数据）。

历史接口 :class:`Grant` / :func:`load_grants` 只暴露组织与代次，
:class:`GrantRecord` / :func:`load_grant_records` 额外携带令牌秘密，
令牌以 :class:`~app.secrets.Secret` 包装，读取方不负责持久化。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.secrets import Secret


@dataclass(frozen=True)
class Grant:
    organization: str
    generation: int
    expires_at: int


def load_grants(path: str | Path = "fixtures/grants.json") -> dict[str, Grant]:
    values = json.loads(Path(path).read_text(encoding="utf-8"))
    result: dict[str, Grant] = {}
    for value in values:
        if value["organization"] in result:
            raise ValueError("组织授权记录重复")
        if value["generation"] < 1:
            raise ValueError("令牌代次无效")
        result[value["organization"]] = Grant(
            value["organization"], value["generation"], value["expires_at"]
        )
    return result


@dataclass(frozen=True)
class GrantRecord:
    organization: str
    generation: int
    expires_at: int
    access_token: Secret
    refresh_token: Secret

    @property
    def grant(self) -> Grant:
        return Grant(self.organization, self.generation, self.expires_at)


def load_grant_records(
    path: str | Path = "fixtures/grants.json",
) -> dict[str, GrantRecord]:
    """读取完整授权记录；秘密字段以 Secret 包装。"""
    values = json.loads(Path(path).read_text(encoding="utf-8"))
    result: dict[str, GrantRecord] = {}
    for value in values:
        org = value["organization"]
        if org in result:
            raise ValueError("组织授权记录重复")
        if value["generation"] < 1:
            raise ValueError("令牌代次无效")
        result[org] = GrantRecord(
            organization=org,
            generation=int(value["generation"]),
            expires_at=int(value["expires_at"]),
            access_token=Secret(value["access_token"]),
            refresh_token=Secret(value["refresh_token"]),
        )
    return result
