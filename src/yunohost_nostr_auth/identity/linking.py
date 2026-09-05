"""Account linking (PLAN.md Phase 5).

Linking a pubkey to a YunoHost account always requires an already
authenticated YunoHost session, verified alongside the Nostr signature over
a linking challenge - an arbitrary pubkey must never be able to claim an
existing account on its own. Replacing or unlinking a key requires the same.
"""

from __future__ import annotations


def link_identity(ynh_username: str, pubkey_hex: str) -> None:
    raise NotImplementedError


def unlink_identity(ynh_username: str) -> None:
    raise NotImplementedError
