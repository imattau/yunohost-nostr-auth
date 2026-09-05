"""Client for nostr_auth's private linked-identity lookup socket."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from pathlib import Path

from yunohost_nostr_auth.config import get_settings

DEFAULT_TIMEOUT_SECONDS = 5


class IdentityLookupError(Exception):
    pass


@dataclass(frozen=True)
class LinkedIdentity:
    linked: bool
    username: str | None


def lookup_identity(
    pubkey: str,
    *,
    socket_path: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> LinkedIdentity:
    path = socket_path if socket_path is not None else get_settings().identity_lookup_socket
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall(json.dumps({"pubkey": pubkey}, separators=(",", ":")).encode() + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
    except OSError as exc:
        raise IdentityLookupError(f"could not reach identity lookup helper: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IdentityLookupError(f"identity lookup helper returned invalid output: {exc}") from exc
    if "error" in payload:
        raise IdentityLookupError(f"identity lookup helper failed: {payload['error']}")
    if not isinstance(payload.get("linked"), bool) or (payload.get("username") is not None and not isinstance(payload["username"], str)):
        raise IdentityLookupError("identity lookup helper returned an invalid response")
    return LinkedIdentity(linked=payload["linked"], username=payload["username"])
