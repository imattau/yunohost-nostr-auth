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

DEFAULT_TIMEOUT_SECONDS = 5


class PortalAuthError(Exception):
    """The forwarded cookie isn't a valid, currently-authenticated session."""


def get_authenticated_username(
    cookie_header: str,
    *,
    base_url: str = "http://127.0.0.1:6788",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Return the ynh_username portal-api associates with `cookie_header`
    (the exact `Cookie` request header value received from the browser,
    e.g. `"yunohost.portal=<jwt>"`).

    Raises PortalAuthError if portal-api rejects the cookie (expired,
    forged, wrong domain, ...) or can't be reached at all - callers must
    treat both the same way: refuse the linking/unlinking action.
    """
    request = urllib.request.Request(
        f"{base_url}/me",
        headers={"Cookie": cookie_header, "Accept": "application/json"},
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

    return username
