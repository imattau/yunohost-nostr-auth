"""Documents the privilege boundary this package is built around - not
enforced here in Python (that's what systemd config in the nostr_auth_ynh
package does), but recorded here as the single place that says which side
of the line each ynh/* module lives on, per PHASE0_INVESTIGATION.md's
Conclusions and its later "Privilege-drop redesign" (a sudo-spawned-per-
request helper doesn't work in containerized installs where the container
sets the kernel's no_new_privs bit - confirmed on a real test install).

Runs as the main daemon's own unprivileged user (never root, never
`ynh-portal`), as `nostr_auth_ynh`'s conf/systemd.service:
    - portal_client.py - asks the real yunohost-portal-api "who is this
                          cookie", never reads the session secret itself.
    - sessions.py       - talks to mint_session_server.py over a Unix
                          socket; holds no privilege of its own.

Runs as `ynh-portal`, as its own separate, always-running systemd service
(`nostr_auth_ynh`'s conf/nostr_auth-mint-session.service) - never invoked
on demand by the daemon above, since systemd starting a `User=ynh-portal`
service from root is a privilege *drop*, not a *gain*, and so isn't
affected by no_new_privs the way spawning `sudo` from the unprivileged
daemon would be:
    - mint_session_server.py - the actual socket listener; checks each
                                connection's SO_PEERCRED before doing
                                anything, since the socket's own file mode
                                can't restrict callers by itself.
    - portal_cookie.py        - reads /etc/yunohost/.ssowat_cookie_secret,
                                 writes /var/cache/yunohost-portal/sessions/.
    - ldap_lookup.py           - anonymous LDAP bind for cn/mail lookup.

Nothing else in this package needs, or should ever be granted, either the
`ynh-portal` account or root.
"""

from __future__ import annotations
