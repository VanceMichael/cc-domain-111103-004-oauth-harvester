"""本地持久化：授权状态存储与逐组织采集台账。

设计约束：
* 授权文件按组织隔离，单组织撤权/失效不触碰其他组织的文件；
* 写入采用临时文件 + 原子替换，文件权限 0600，进程在写入前退出不会留下半截 JSON；
* 刷新“已发起未确认”的状态（含 attempt id 与待确认代次）必须落盘，
  恢复时据此决定幂等重放还是要求重新授权，而不是盲目重用旧 refresh token；
* 采集台账用 SQLite 唯一约束保证重复页面/重复记录不会重复落入数据集。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

from app.auth import AuthStatus
from app.oauth import GrantRecord
from app.secrets import Secret


@dataclass(frozen=True)
class PendingRefresh:
    """一次已发起、结果尚未确认的刷新过程。"""

    attempt_id: str
    expected_generation: int
    started_at: int
    refresh_fingerprint: str


@dataclass
class AuthState:
    organization: str
    generation: int
    expires_at: int
    access_token: Secret
    refresh_token: Secret
    status: AuthStatus = AuthStatus.ACTIVE
    paused: bool = False
    pending: PendingRefresh | None = None
    reauth_reason: str | None = None

    def to_wire(self) -> dict:
        """序列化为可落盘的普通字典（秘密仅出现在 0600 文件内）。"""
        return {
            "organization": self.organization,
            "generation": self.generation,
            "expires_at": self.expires_at,
            "access_token": self.access_token.reveal(),
            "refresh_token": self.refresh_token.reveal(),
            "status": self.status.value,
            "paused": self.paused,
            "pending": asdict(self.pending) if self.pending else None,
            "reauth_reason": self.reauth_reason,
        }

    @classmethod
    def from_wire(cls, data: dict) -> "AuthState":
        return cls(
            organization=data["organization"],
            generation=int(data["generation"]),
            expires_at=int(data["expires_at"]),
            access_token=Secret(data["access_token"]),
            refresh_token=Secret(data["refresh_token"]),
            status=AuthStatus(data["status"]),
            paused=bool(data.get("paused", False)),
            pending=PendingRefresh(**data["pending"]) if data.get("pending") else None,
            reauth_reason=data.get("reauth_reason"),
        )

    def redacted(self) -> dict:
        """供操作者界面/报告使用的脱敏视图。"""
        return {
            "organization": self.organization,
            "generation": self.generation,
            "expires_at": self.expires_at,
            "access_token": self.access_token.fingerprint(),
            "refresh_token": self.refresh_token.fingerprint(),
            "status": self.status.value,
            "paused": self.paused,
            "pending_attempt": self.pending.attempt_id if self.pending else None,
            "pending_generation": self.pending.expected_generation
            if self.pending
            else None,
            "reauth_reason": self.reauth_reason,
            "next_action": next_action(self),
        }


def next_action(state: AuthState) -> str:
    """操作者视角：该组织下一步需要的授权动作。"""
    if state.status is AuthStatus.REVOKED:
        return "重新登记该组织的授权（当前授权已撤回）"
    if state.status is AuthStatus.REAUTH_REQUIRED:
        reason = state.reauth_reason or "refresh token 已失效"
        return f"引导该组织重新完成授权以换取新的 refresh token（{reason}）"
    if state.status is AuthStatus.REFRESH_PENDING:
        return (
            "启动时自动确认挂起的刷新 attempt "
            f"{state.pending.attempt_id if state.pending else ''}；若服务端无法重放则重新授权"
        )
    if state.paused:
        return "调用恢复接口继续采集（令牌本身仍有效）"
    return "无需动作，采集可正常进行"


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)  # 原子替换：崩溃只会留下旧文件或新文件，不会出现半截文件


class AuthStore:
    """按组织隔离的授权状态存储。"""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        os.chmod(self._root, 0o700)
        self._lock = threading.Lock()
        self._cache: dict[str, AuthState] = {}

    def _path(self, organization: str) -> Path:
        if "/" in organization or ".." in organization:
            raise ValueError("非法组织标识")
        return self._root / f"{organization}.json"

    def bootstrap(self, records: dict[str, GrantRecord]) -> None:
        """首次登记授权；已存在的组织文件保持不动（保留持久化代次）。"""
        for record in records.values():
            path = self._path(record.organization)
            if path.exists():
                continue
            state = AuthState(
                organization=record.organization,
                generation=record.generation,
                expires_at=record.expires_at,
                access_token=record.access_token,
                refresh_token=record.refresh_token,
            )
            _atomic_write_json(path, state.to_wire())

    def load(self, organization: str) -> AuthState:
        with self._lock:
            cached = self._cache.get(organization)
            if cached is not None:
                return cached
            path = self._path(organization)
            if not path.exists():
                raise KeyError(f"未知组织：{organization}")
            state = AuthState.from_wire(
                json.loads(path.read_text(encoding="utf-8"))
            )
            self._cache[organization] = state
            return state

    def save(self, state: AuthState) -> None:
        with self._lock:
            _atomic_write_json(self._path(state.organization), state.to_wire())
            self._cache[state.organization] = state

    def all_orgs(self) -> list[str]:
        return sorted(p.stem for p in self._root.glob("*.json"))

    def redacted_snapshot(self, organization: str | None = None) -> list[dict]:
        orgs = [organization] if organization else self.all_orgs()
        return [self.load(org).redacted() for org in orgs]


class HarvestStore:
    """逐组织 SQLite 采集台账：页面幂等 + 记录去重。"""

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self._path.parent, 0o700)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS page_journal (
                page_key      TEXT PRIMARY KEY,
                generation    INTEGER NOT NULL,
                next_cursor   TEXT,
                completed     INTEGER NOT NULL DEFAULT 0,
                fetched_at    INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS records (
                record_id     TEXT PRIMARY KEY,
                page_key      TEXT NOT NULL,
                generation    INTEGER NOT NULL,
                payload       TEXT NOT NULL,
                inserted_at   INTEGER NOT NULL
            );
            """
        )
        self._conn.commit()
        os.chmod(self._path, 0o600)

    # -- 页面台账 ----------------------------------------------------------

    def is_page_done(self, page_key: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM page_journal WHERE page_key = ? AND completed = 1",
                (page_key,),
            ).fetchone()
            return row is not None

    def last_cursor(self) -> str | None:
        """最近已完成页面给出的下一页游标；没有台账时从头开始。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT next_cursor FROM page_journal "
                "WHERE completed = 1 ORDER BY fetched_at DESC LIMIT 1"
            ).fetchone()
            return row[0] if row and row[0] else None

    def next_cursor_for(self, page_key: str) -> str | None:
        """指定已完成页面记录的下一页游标；末页返回 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT next_cursor FROM page_journal WHERE page_key = ?",
                (page_key,),
            ).fetchone()
            return row[0] if row else None

    def mark_page_completed(
        self,
        page_key: str,
        generation: int,
        next_cursor: str | None,
        now: int,
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO page_journal(page_key, generation, next_cursor, "
                "completed, fetched_at) VALUES (?, ?, ?, 1, ?) "
                "ON CONFLICT(page_key) DO UPDATE SET "
                "generation=excluded.generation, next_cursor=excluded.next_cursor, "
                "completed=1, fetched_at=excluded.fetched_at",
                (page_key, generation, next_cursor, now),
            )
            self._conn.commit()

    # -- 记录落库（去重） ---------------------------------------------------

    def insert_records(
        self, records: list[dict], page_key: str, generation: int, now: int
    ) -> int:
        """返回真正新插入的记录数；重复 record_id 被静默跳过。"""
        inserted = 0
        with self._lock:
            for record in records:
                record_id = str(record["id"])
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO records"
                    "(record_id, page_key, generation, payload, inserted_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        record_id,
                        page_key,
                        generation,
                        json.dumps(record, ensure_ascii=False),
                        now,
                    ),
                )
                inserted += cur.rowcount
            self._conn.commit()
        return inserted

    def counts(self) -> dict[str, int]:
        with self._lock:
            pages = self._conn.execute(
                "SELECT COUNT(*) FROM page_journal WHERE completed = 1"
            ).fetchone()[0]
            rows = self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        return {"pages_completed": pages, "records": rows}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
