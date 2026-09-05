"""ynh_username <-> Nostr pubkey mapping store (PLAN.md Phase 4).

SQLite-backed. Pubkeys are stored as canonical hex, never as npub - npub is
decoded/encoded only at the UI boundary. One pubkey per user initially; the
schema leaves room for more later.

    users
    -----
    ynh_username
    pubkey
    created_at
    last_used
    enabled
"""

from __future__ import annotations

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    ynh_username TEXT PRIMARY KEY,
    pubkey       TEXT NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used    INTEGER,
    enabled      INTEGER NOT NULL DEFAULT 1
);
"""
