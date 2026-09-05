"""The one place this daemon reaches across the privilege boundary into
`ynh-portal` territory to mint a real YunoHost portal session.

Per PHASE0_INVESTIGATION.md, only the `ynh-portal` system user (or root) can
read /etc/yunohost/.ssowat_cookie_secret or write to
/var/cache/yunohost-portal/sessions/ - this unprivileged daemon can do
neither. `mint_session` is expected to shell out (e.g. `sudo -u ynh-portal`)
to a small, separately-packaged helper that reproduces the exact
yunohost.portal JWT + session-touch-file shape documented there, rather
than reimplementing that logic in-process here - so the packaging
(nostr_auth_ynh's scripts/install, plus the sudoers rule restricting which
user can invoke which fixed helper binary/args) is what actually enforces
least privilege, not this function.

Not yet implemented: needs the privilege-drop mechanism decided (Phase 2
open item in PHASE0_INVESTIGATION.md) before this can do anything real.
"""

from __future__ import annotations


def mint_session(ynh_username: str):
    raise NotImplementedError(
        "Needs the ynh-portal privilege-drop helper from nostr_auth_ynh - "
        "see PHASE0_INVESTIGATION.md's Conclusions"
    )
