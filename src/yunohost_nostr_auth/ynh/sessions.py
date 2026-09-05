"""The one place this daemon reaches across the privilege boundary into
`ynh-portal` territory to mint a real YunoHost portal session.

Per PHASE0_INVESTIGATION.md, only the `ynh-portal` system user (or root)
can read /etc/yunohost/.ssowat_cookie_secret or write to
/var/cache/yunohost-portal/sessions/ - this unprivileged daemon can do
neither. `mint_session` asks `mint_session_server.py` - a separate,
always-running systemd service with `User=ynh-portal` - over a Unix
socket.

This is deliberately *not* a `sudo`/setuid call spawned per request: that
was the original design, and it doesn't work in containerized YunoHost
installs where the container itself sets the kernel's "no new privileges"
bit, permanently blocking any process from gaining privilege via execve of
a setuid binary (confirmed on a real test install - see
PHASE0_INVESTIGATION.md's "Privilege-drop redesign"). A separate service
already started as ynh-portal by systemd-as-root doesn't hit that
restriction, since it's a privilege drop by an already-privileged
supervisor, not a gain by this process.

The packaging (nostr_auth_ynh's conf/nostr_auth-mint-session.service) is
what actually runs that server as ynh-portal - this function just talks to
whatever's listening on the socket.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from pathlib import Path

from yunohost_nostr_auth.config import get_settings

DEFAULT_TIMEOUT_SECONDS = 10


class SessionMintError(Exception):
    pass


@dataclass(frozen=True)
class MintedSession:
    cookie_name: str
    token: str
    max_age: int


def _read_line(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def mint_session(
    ynh_username: str,
    host: str,
    *,
    socket_path: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> MintedSession:
    settings = get_settings()
    socket_path = socket_path if socket_path is not None else settings.mint_session_socket

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(socket_path))
            sock.sendall(json.dumps({"username": ynh_username, "host": host}).encode() + b"\n")
            raw = _read_line(sock)
    except OSError as e:
        raise SessionMintError(f"could not reach session-mint helper: {e}") from e

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SessionMintError(f"session-mint helper returned unexpected output: {e}") from e

    if "error" in payload:
        raise SessionMintError(f"session-mint helper failed: {payload['error']}")

    try:
        token = payload["token"]
        max_age = payload["max_age"]
    except (KeyError, TypeError) as e:
        raise SessionMintError(f"session-mint helper response missing {e}") from e

    return MintedSession(cookie_name="yunohost.portal", token=token, max_age=max_age)
