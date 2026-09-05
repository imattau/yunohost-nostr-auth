"""Documents the privilege boundary this package is built around - not
enforced here in Python (that's what sudoers/systemd config in the
nostr_auth_ynh package does), but recorded here as the single place that
says which side of the line each ynh/* module lives on, per
PHASE0_INVESTIGATION.md's Conclusions.

Runs as the main daemon's own unprivileged user (never root, never
`ynh-portal`):
    - portal_client.py    - asks the real yunohost-portal-api "who is this
                             cookie", never reads the session secret itself.
    - sessions.py          - shells out to the helper below via
                             `sudo -n -u ynh-portal`; holds no privilege of
                             its own.

Runs as `ynh-portal` (invoked only via the fixed-argument sudoers rule
nostr_auth_ynh's scripts/install adds - never as this daemon's own user):
    - mint_session_helper.py - the actual sudo entry point.
    - portal_cookie.py       - reads /etc/yunohost/.ssowat_cookie_secret,
                                writes /var/cache/yunohost-portal/sessions/.
    - ldap_lookup.py          - anonymous LDAP bind for cn/mail lookup.

Nothing else in this package needs, or should ever be granted, either the
`ynh-portal` account or root.
"""

from __future__ import annotations
