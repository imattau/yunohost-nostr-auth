"""Client for nostr_auth's private relay-list lookup socket."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from pathlib import Path

from yunohost_nostr_auth.config import get_settings

DEFAULT_TIMEOUT_SECONDS = 10


class RelayLookupError(Exception):
    pass


@dataclass(frozen=True)
class LookedUpRelay:
    url: str
    read: bool
    write: bool


@dataclass(frozen=True)
class RelayLookupResult:
    linked: bool
    relays: list[LookedUpRelay]
    fetched_at: int | None


def lookup_relays(
    pubkey: str,
    *,
    socket_path: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> RelayLookupResult:
    path = socket_path if socket_path is not None else get_settings().relay_lookup_socket
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(path))
            sock.sendall(json.dumps({"pubkey": pubkey}, separators=(",", ":")).encode() + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
    except OSError as exc:
        raise RelayLookupError(f"could not reach relay lookup helper: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RelayLookupError(f"relay lookup helper returned invalid output: {exc}") from exc
    if "error" in payload:
        raise RelayLookupError(f"relay lookup helper failed: {payload['error']}")
    if not isinstance(payload.get("linked"), bool) or not isinstance(payload.get("relays"), list):
        raise RelayLookupError("relay lookup helper returned an invalid response")
    try:
        relay_entries = [LookedUpRelay(url=r["url"], read=r["read"], write=r["write"]) for r in payload["relays"]]
    except (KeyError, TypeError) as exc:
        raise RelayLookupError("relay lookup helper returned an invalid relay entry") from exc
    return RelayLookupResult(linked=payload["linked"], relays=relay_entries, fetched_at=payload.get("fetched_at"))
