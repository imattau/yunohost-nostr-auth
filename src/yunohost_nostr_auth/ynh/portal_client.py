"""Identify the browser's already-authenticated YunoHost user by forwarding
their own `yunohost.portal` cookie to the real yunohost-portal-api's `GET
/me`, over localhost.

This is the one part of the login/link flow this unprivileged daemon can
do entirely on its own: per PHASE0_INVESTIGATION.md, only the `ynh-portal`
system user (or root) can read `/etc/yunohost/.ssowat_cookie_secret` to
verify that cookie's signature directly, so we don't try - we let the
process that already holds that privilege (yunohost-portal-api itself)
answer "who is this" for us, and trust its answer. Nothing here ever
touches the cookie secret or the session-file store.

PLAN.md Phase 5 only needs this "who is currently logged in" fact to gate
account linking - it does not need write access to sessions, which is
ynh/sessions.py's job instead.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEFAULT_TIMEOUT_SECONDS = 5

# portal.py's portal_me() (yunohost-core src/portal.py) excludes the
# username's own cn and "all_users" from the returned `groups` list, but
# does include "admins" for a server administrator - the same membership
# check YunoHost's own portal.py uses for its admin-gated actions
# (`"cn=admins,ou=groups,dc=yunohost,dc=org" in current_user["memberOf"]`).
ADMIN_GROUP = "admins"


class PortalAuthError(Exception):
    """The forwarded cookie isn't a valid, currently-authenticated session."""


@dataclass(frozen=True)
class AuthenticatedSession:
    username: str
    groups: list[str] = field(default_factory=list)

    @property
    def is_admin(self) -> bool:
        return ADMIN_GROUP in self.groups


def get_authenticated_session(
    cookie_header: str,
    *,
    host: str,
    base_url: str = "http://127.0.0.1:6788",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> AuthenticatedSession:
    """Return the ynh_username and group memberships portal-api associates
    with `cookie_header` (the exact `Cookie` request header value received
    from the browser, e.g. `"yunohost.portal=<jwt>"`).

    `host` must be the original request's `Host` header (the domain the
    browser actually used) - ldap_ynhuser.py's `get_session_cookie()`
    rejects the session outright if the cookie's `host` claim doesn't
    match the request's `Host` header (PHASE0_INVESTIGATION.md), and
    without setting it explicitly here, urllib sends `127.0.0.1:6788` (the
    literal address we're connecting to) instead - confirmed on a real
    install, where every session was rejected with a 401 until this was
    added.

    Raises PortalAuthError if portal-api rejects the cookie (expired,
    forged, wrong domain, ...) or can't be reached at all - callers must
    treat both the same way: refuse the linking/unlinking action.
    """
    request = urllib.request.Request(
        f"{base_url}/me",
        headers={"Cookie": cookie_header, "Accept": "application/json", "Host": host},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read())
    except urllib.error.HTTPError as e:
        raise PortalAuthError(f"portal-api rejected the session (HTTP {e.code})") from e
    except urllib.error.URLError as e:
        raise PortalAuthError(f"could not reach portal-api: {e}") from e
    except json.JSONDecodeError as e:
        raise PortalAuthError(f"portal-api returned a non-JSON response: {e}") from e

    username = body.get("username")
    if not username or not isinstance(username, str):
        raise PortalAuthError("portal-api response did not include a username")

    groups = body.get("groups")
    if not isinstance(groups, list):
        groups = []

    return AuthenticatedSession(username=username, groups=[g for g in groups if isinstance(g, str)])


def get_authenticated_username(
    cookie_header: str,
    *,
    host: str,
    base_url: str = "http://127.0.0.1:6788",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Convenience wrapper over :func:`get_authenticated_session` for
    every caller that only needs the username, not group membership.
    """
    return get_authenticated_session(
        cookie_header, host=host, base_url=base_url, timeout=timeout
    ).username
