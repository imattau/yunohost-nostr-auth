"""Account linking (PLAN.md Phase 5).

Linking or unlinking a pubkey always requires both:
  1. an already-authenticated YunoHost session (confirmed via
     ynh/portal_client.py's call to the real portal-api, never by us
     re-deriving the session cookie's signature - see that module's
     docstring), and
  2. a Nostr signature over a challenge minted specifically for this
     action (verified via auth/nostr_verify.py).

An arbitrary Nostr pubkey must never be able to claim an existing account
on its own - hence requiring (1). And (1) alone isn't enough either,
otherwise a stolen/reused browser session could silently attach an
attacker's pubkey - hence requiring (2) as well.
"""

from __future__ import annotations

from yunohost_nostr_auth.auth import nostr_verify
from yunohost_nostr_auth.auth.challenge import Challenge
from yunohost_nostr_auth.identity.mappings import MappingStore
from yunohost_nostr_auth.ynh import portal_client

LINK_ACTION = "yunohost-link"


class LinkingError(ValueError):
    """The session, the challenge, or the signed event failed to check out."""


def confirm_and_link(
    store: MappingStore,
    *,
    cookie_header: str,
    host: str,
    challenge: Challenge | None,
    event_json: str,
    portal_api_base_url: str = "http://127.0.0.1:6788",
) -> str:
    """Verify both requirements above and record the mapping.

    `host` must be the original request's `Host` header - see
    ynh/portal_client.py's docstring for why it has to be forwarded
    explicitly rather than left to default.

    `challenge` must be the already-`consume()`d Challenge matching the
    nonce the client signed (callers look it up by the event's `challenge`
    tag before calling this, so an unknown/expired/reused nonce never gets
    this far). Returns the linked ynh_username.
    """
    if challenge is None:
        raise LinkingError("unknown, expired, or already-used challenge")
    if challenge.action != LINK_ACTION:
        raise LinkingError(f"challenge was not issued for {LINK_ACTION!r}")

    try:
        username = portal_client.get_authenticated_username(
            cookie_header, host=host, base_url=portal_api_base_url
        )
    except portal_client.PortalAuthError as e:
        raise LinkingError(f"not currently logged in to YunoHost: {e}") from e

    try:
        pubkey = nostr_verify.verify_challenge_response(
            event_json,
            expected_nonce=challenge.nonce,
            expected_domain=challenge.domain,
            expected_action=challenge.action,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
        )
    except nostr_verify.InvalidEvent as e:
        raise LinkingError(str(e)) from e

    store.link(username, pubkey)
    return username


def confirm_and_unlink(
    store: MappingStore,
    *,
    cookie_header: str,
    host: str,
    portal_api_base_url: str = "http://127.0.0.1:6788",
) -> str:
    """Unlink whichever identity belongs to the session in `cookie_header`.

    Deliberately does not require a fresh Nostr signature (the user may
    have lost the key they're unlinking) - the authenticated YunoHost
    session alone is sufficient here, matching PLAN.md Phase 12's recovery
    model ("password login -> unlink old key -> link new key").
    """
    try:
        username = portal_client.get_authenticated_username(
            cookie_header, host=host, base_url=portal_api_base_url
        )
    except portal_client.PortalAuthError as e:
        raise LinkingError(f"not currently logged in to YunoHost: {e}") from e

    store.unlink(username)
    return username
