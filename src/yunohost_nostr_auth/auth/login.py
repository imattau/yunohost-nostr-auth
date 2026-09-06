"""Ties challenge verification, the pubkey->user mapping, and session
minting into the actual login flow (PLAN.md Phase 1's diagram)."""

from __future__ import annotations

from yunohost_nostr_auth.auth import nostr_verify
from yunohost_nostr_auth.auth import session as ynh_session
from yunohost_nostr_auth.auth.challenge import Challenge
from yunohost_nostr_auth.identity.mappings import MappingStore
from yunohost_nostr_auth.ynh.sessions import MintedSession

LOGIN_ACTION = "yunohost-login"


class LoginError(ValueError):
    """The challenge, the signed event, or the pubkey->account mapping failed to check out."""


def authenticate(
    store: MappingStore,
    *,
    challenge: Challenge | None,
    event_json: str,
    clock_skew: int = 60,
) -> MintedSession:
    """Verify a signed login event against `challenge` and, if the
    signer's pubkey is linked to a YunoHost account, mint a session for it.

    `challenge` must already have been looked up and `consume()`d by nonce
    (from the event's `challenge` tag) before calling this, so a
    replayed/unknown/expired nonce never reaches this function at all.
    """
    if challenge is None:
        raise LoginError("unknown, expired, or already-used challenge")
    if challenge.action != LOGIN_ACTION:
        raise LoginError(f"challenge was not issued for {LOGIN_ACTION!r}")

    try:
        pubkey = nostr_verify.verify_challenge_response(
            event_json,
            expected_nonce=challenge.nonce,
            expected_domain=challenge.domain,
            expected_action=challenge.action,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
            clock_skew=clock_skew,
        )
    except nostr_verify.InvalidEvent as e:
        raise LoginError(str(e)) from e

    identity = store.get_by_pubkey(pubkey)
    if identity is None:
        raise LoginError("this pubkey is not linked to any YunoHost account")

    if identity.identity_id is not None:
        store.touch_identity(identity.identity_id)
    else:  # Compatibility with lightweight MappingStore test doubles.
        store.touch_last_used(identity.ynh_username)
    return ynh_session.create_ynh_session(identity.ynh_username, challenge.domain)
