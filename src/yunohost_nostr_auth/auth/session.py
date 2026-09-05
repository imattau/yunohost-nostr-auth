"""Entry point the HTTP handlers call to turn a verified Nostr login into a
YunoHost portal session.

Per PHASE0_INVESTIGATION.md, there is no password-less login function this
service can call from its own (unprivileged) process: minting a
`yunohost.portal` session cookie requires reading
`/etc/yunohost/.ssowat_cookie_secret` (mode 400, owned `ynh-portal:root`)
and writing to `/var/cache/yunohost-portal/sessions/` (mode 710, owned
`ynh-portal:www-data`) - both readable/writable only by the `ynh-portal`
system user or root, neither of which this daemon should ever run as.

So this function does not do the minting itself - it delegates to
ynh/sessions.py, which invokes a separately-privileged helper running as
ynh-portal (PLAN.md's "least privilege" instruction). Keeping that call
behind this module, rather than calling the helper directly from
server.py, is what lets ynh/permissions.py document and enforce the
privilege boundary in one place.
"""

from __future__ import annotations

from yunohost_nostr_auth.ynh import sessions as ynh_sessions


def create_ynh_session(ynh_username: str, host: str) -> ynh_sessions.MintedSession:
    """Mint a `yunohost.portal` session for an already Nostr-verified user.

    `host` must be the exact `Host` header of the request that reached us
    (the same value used as the challenge's `domain` claim) - it becomes
    the session's `host` claim, which YunoHost's own session check
    (ldap_ynhuser.py's `get_session_cookie`) and SSOwat both compare
    against the request's actual Host before accepting the cookie.

    The resulting session's `pwd` claim is an encrypted empty string, not a
    real LDAP password (we never have one) - profile edits and legacy
    Basic-Auth-only apps won't work from a Nostr-only session. See
    PHASE0_INVESTIGATION.md's Conclusions for why that's a permanent
    limitation of this session design, not a bug here.
    """
    return ynh_sessions.mint_session(ynh_username, host)
