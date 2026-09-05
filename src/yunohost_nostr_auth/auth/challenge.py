"""Single-use, domain- and action-bound login/link challenges (PLAN.md Phase 3).

A challenge binds at minimum: nonce, domain, requested action, issued time,
expiry. It must be consumed atomically on successful authentication so it
cannot be replayed - against this server or another YunoHost instance.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from time import time

DEFAULT_TTL_SECONDS = 90  # PLAN.md Phase 13: 30-120 second expiry


@dataclass(frozen=True)
class Challenge:
    nonce: str
    domain: str
    action: str
    issued_at: int
    expires_at: int


def new_challenge(domain: str, action: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> Challenge:
    now = int(time())
    return Challenge(
        nonce=secrets.token_urlsafe(32),
        domain=domain,
        action=action,
        issued_at=now,
        expires_at=now + ttl_seconds,
    )


class ChallengeStore:
    """Tracks outstanding challenges and consumes them exactly once.

    TODO: back with SQLite (matching identity/mappings.py) rather than an
    in-memory dict once the service needs to survive process restarts.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl_seconds = ttl_seconds
        self._pending: dict[str, Challenge] = {}

    def issue(self, domain: str, action: str) -> Challenge:
        challenge = new_challenge(domain, action, self._ttl_seconds)
        self._pending[challenge.nonce] = challenge
        return challenge

    def consume(self, nonce: str) -> Challenge | None:
        challenge = self._pending.pop(nonce, None)
        if challenge is None:
            return None
        if challenge.expires_at < int(time()):
            return None
        return challenge
