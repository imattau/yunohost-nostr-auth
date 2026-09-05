"""YunoHost user lookup, scoped to only what this service needs.

Not general LDAP/root access - just enough to confirm a ynh_username exists
and is enabled, for the mapping in identity/mappings.py.
"""

from __future__ import annotations


def user_exists(ynh_username: str) -> bool:
    raise NotImplementedError
