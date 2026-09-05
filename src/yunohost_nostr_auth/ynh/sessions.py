"""The one place this daemon reaches across the privilege boundary into
`ynh-portal` territory to mint a real YunoHost portal session.

Per PHASE0_INVESTIGATION.md, only the `ynh-portal` system user (or root)
can read /etc/yunohost/.ssowat_cookie_secret or write to
/var/cache/yunohost-portal/sessions/ - this unprivileged daemon can do
neither. `mint_session` shells out via `sudo -u ynh-portal` to
`yunohost-nostr-auth-mint-session` (ynh/mint_session_helper.py), which
reproduces the exact yunohost.portal JWT + session-touch-file shape
documented there (ynh/portal_cookie.py) rather than this process
reimplementing that logic itself.

The packaging (nostr_auth_ynh's scripts/install, plus the sudoers rule
restricting exactly which user can invoke exactly this one helper binary)
is what actually enforces least privilege - this function just shells out
to whatever `sudo` allows, and trusts that boundary to be configured
correctly.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from yunohost_nostr_auth.config import get_settings


class SessionMintError(Exception):
    pass


@dataclass(frozen=True)
class MintedSession:
    cookie_name: str
    token: str
    max_age: int


def mint_session(
    ynh_username: str,
    host: str,
    *,
    helper_path: Path | None = None,
    helper_user: str | None = None,
    timeout: float = 10,
) -> MintedSession:
    settings = get_settings()
    helper_path = helper_path if helper_path is not None else settings.mint_session_helper
    helper_user = helper_user if helper_user is not None else settings.mint_session_user

    try:
        result = subprocess.run(
            ["sudo", "-n", "-u", helper_user, "--", str(helper_path), ynh_username, host],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SessionMintError(f"could not invoke session-mint helper: {e}") from e

    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        raise SessionMintError(f"session-mint helper failed: {stderr or 'no output'}")

    try:
        payload = json.loads(result.stdout)
        token = payload["token"]
        max_age = payload["max_age"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise SessionMintError(f"session-mint helper returned unexpected output: {e}") from e

    return MintedSession(cookie_name="yunohost.portal", token=token, max_age=max_age)
