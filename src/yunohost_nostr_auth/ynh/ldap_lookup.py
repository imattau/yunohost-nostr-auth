"""Look up a YunoHost user's display name and primary email, for the
`fullname`/`email` claims a minted session cookie carries (see
ynh/portal_cookie.py).

Only ever called from mint_session_helper.py, running as `ynh-portal`.
Per PHASE0_INVESTIGATION.md, `moulinette`'s `LDAPInterface` binds
*anonymously* over the `ldapi:///var/run/slapd/ldapi` unix socket whenever
the calling process isn't root (`src/utils/ldap.py`'s `__init__`) - which
is exactly `yunohost-portal-api`'s own situation, running as `ynh-portal`.
This module does the same anonymous bind and the same search
`portal.py`'s `_get_user_infos()` does (`ou=users`, `uid={username}`,
attrs `cn`/`mail`), on the theory that whatever slapd ACL already lets
`yunohost-portal-api` read those attributes anonymously will do the same
for us, since we run as the same user over the same local socket.

**Not yet verified against a live YunoHost 12 install** - if slapd's ACLs
turn out to be scoped to the `yunohost-portal-api` process some other way
(not just "anonymous over this socket"), this will need a different
approach (e.g. a narrow read-only LDAP service account for `ynh-portal`
instead of anonymous bind).

Imports `ldap` (the `python-ldap` package) lazily, expecting it to come
from the system site-packages (Debian's `python3-ldap`, which YunoHost
itself already depends on) via the venv's `--system-site-packages` flag -
not from PyPI, to avoid needing libldap/libsasl headers to build it. See
nostr_auth_ynh's scripts/_common.sh.
"""

from __future__ import annotations

from dataclasses import dataclass

LDAP_URI = "ldapi:///var/run/slapd/ldapi"
USERS_BASE_DN = "ou=users,dc=yunohost,dc=org"


class UserLookupError(Exception):
    pass


@dataclass(frozen=True)
class UserContactInfo:
    fullname: str
    email: str


def get_user_contact_info(ynh_username: str) -> UserContactInfo:
    import ldap  # noqa: PLC0415 - see module docstring: system site-packages only
    import ldap.filter

    con = ldap.initialize(LDAP_URI)
    try:
        con.simple_bind_s()  # anonymous bind - see module docstring
        escaped_username = ldap.filter.escape_filter_chars(ynh_username)
        results = con.search_s(
            USERS_BASE_DN,
            ldap.SCOPE_SUBTREE,
            f"(uid={escaped_username})",
            ["cn", "mail"],
        )
    except ldap.LDAPError as e:
        raise UserLookupError(f"LDAP error looking up {ynh_username!r}: {e}") from e
    finally:
        con.unbind_s()

    if len(results) != 1:
        raise UserLookupError(f"user {ynh_username!r} not found (or ambiguous) in LDAP")

    _dn, attrs = results[0]
    try:
        fullname = attrs["cn"][0].decode()
        email = attrs["mail"][0].decode()
    except (KeyError, IndexError) as e:
        raise UserLookupError(f"user {ynh_username!r} is missing cn/mail attributes") from e

    return UserContactInfo(fullname=fullname, email=email)
