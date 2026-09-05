"""ynh_username <-> Nostr pubkey mapping store (PLAN.md Phase 4).

SQLite-backed. Pubkeys are stored as canonical hex, never as npub - npub is
decoded/encoded only at the UI boundary (see identity/npub.py). One pubkey
per user; each pubkey may belong to at most one user (both enforced at the
schema level), matching PLAN.md Phase 4's "support one pubkey per user
initially."
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    ynh_username TEXT PRIMARY KEY,
    pubkey       TEXT NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used    INTEGER,
    enabled      INTEGER NOT NULL DEFAULT 1
);
"""


@dataclass(frozen=True)
class Identity:
    ynh_username: str
    pubkey: str
    created_at: int
    last_used: int | None
    enabled: bool


class PubkeyAlreadyLinked(ValueError):
    """Raised when linking a pubkey that's already linked to a different user."""


class MappingStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.execute(SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def link(self, ynh_username: str, pubkey_hex: str) -> None:
        """Link `pubkey_hex` to `ynh_username`, replacing any identity
        previously linked to that user (PLAN.md Phase 5's "replace
        identity"). Refuses if the pubkey is already linked to a
        *different* user - a pubkey must be claimed by one account only.
        """
        with closing(self._connect()) as conn:
            existing = conn.execute(
                "SELECT ynh_username FROM users WHERE pubkey = ?", (pubkey_hex,)
            ).fetchone()
            if existing is not None and existing["ynh_username"] != ynh_username:
                raise PubkeyAlreadyLinked(
                    f"pubkey already linked to a different account ({existing['ynh_username']!r})"
                )

            conn.execute(
                """
                INSERT INTO users (ynh_username, pubkey, created_at, enabled)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(ynh_username) DO UPDATE SET
                    pubkey = excluded.pubkey,
                    created_at = excluded.created_at,
                    last_used = NULL,
                    enabled = 1
                """,
                (ynh_username, pubkey_hex, int(time.time())),
            )
            conn.commit()

    def unlink(self, ynh_username: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute("DELETE FROM users WHERE ynh_username = ?", (ynh_username,))
            conn.commit()

    def get_by_pubkey(self, pubkey_hex: str) -> Identity | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE pubkey = ? AND enabled = 1", (pubkey_hex,)
            ).fetchone()
            return self._row_to_identity(row) if row else None

    def get_by_username(self, ynh_username: str) -> Identity | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE ynh_username = ?", (ynh_username,)
            ).fetchone()
            return self._row_to_identity(row) if row else None

    def touch_last_used(self, ynh_username: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE users SET last_used = ? WHERE ynh_username = ?",
                (int(time.time()), ynh_username),
            )
            conn.commit()

    def list_all(self) -> list[Identity]:
        """For the admin CLI (PLAN.md Phase 14: `yunohost nostr-auth users`)."""
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY ynh_username").fetchall()
            return [self._row_to_identity(row) for row in rows]

    @staticmethod
    def _row_to_identity(row: sqlite3.Row) -> Identity:
        return Identity(
            ynh_username=row["ynh_username"],
            pubkey=row["pubkey"],
            created_at=row["created_at"],
            last_used=row["last_used"],
            enabled=bool(row["enabled"]),
        )
