"""Private, read-only linked-identity lookup service.

This is deliberately a separate socket from the privileged session-mint
helper. It answers exactly one question for one pubkey and cannot enumerate
or mutate the identity database. Consumer authorization is enforced both by
the socket's filesystem group and by SO_PEERCRED membership checking.
"""

from __future__ import annotations

import argparse
import grp
import json
import logging
import os
import pwd
import re
import socket
import socketserver
import struct
from pathlib import Path

from yunohost_nostr_auth.config import get_settings
from yunohost_nostr_auth.identity.mappings import MappingStore

logger = logging.getLogger("yunohost_nostr_auth.identity_lookup_server")

DEFAULT_SOCKET_PATH = Path("/run/nostr_auth-lookup/lookup.sock")
DEFAULT_GROUP = "nostr-auth-lookup"
_UCRED_FORMAT = "3i"
_PUBKEY_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_REQUEST_BYTES = 256


def _peer_credentials(conn: socket.socket) -> tuple[int, int]:
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize(_UCRED_FORMAT))
    _pid, uid, gid = struct.unpack(_UCRED_FORMAT, creds)
    return uid, gid


def _read_line(conn: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n") and len(data) <= _MAX_REQUEST_BYTES:
        chunk = conn.recv(min(256, _MAX_REQUEST_BYTES + 1 - len(data)))
        if not chunk:
            break
        data += chunk
    if len(data) > _MAX_REQUEST_BYTES:
        raise ValueError("request exceeds size limit")
    return data


def _uid_in_group(uid: int, gid: int, group_name: str) -> bool:
    # The MCP root broker may independently re-check authorization. Root is
    # already trusted by the operating system and cannot be made less
    # privileged by this lookup socket, but it still receives only the same
    # single-key response as every other caller.
    if uid == 0:
        return True
    try:
        group = grp.getgrnam(group_name)
        username = pwd.getpwuid(uid).pw_name
    except KeyError:
        return False
    return gid == group.gr_gid or username in group.gr_mem


class _Handler(socketserver.BaseRequestHandler):
    server: "_Server"

    def handle(self) -> None:
        conn: socket.socket = self.request
        try:
            uid, gid = _peer_credentials(conn)
            if not _uid_in_group(uid, gid, self.server.allowed_group):
                self._respond({"error": "forbidden"})
                return
            request = json.loads(_read_line(conn))
            pubkey = request["pubkey"]
            if set(request) != {"pubkey"} or not isinstance(pubkey, str) or not _PUBKEY_RE.fullmatch(pubkey):
                raise ValueError("pubkey must be 64 lowercase hexadecimal characters")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            self._respond({"error": f"bad request: {exc}"})
            return

        try:
            identity = self.server.mappings.get_by_pubkey(pubkey)
            self._respond(
                {"linked": identity is not None, "username": identity.ynh_username if identity else None}
            )
        except Exception as exc:  # pragma: no cover - defensive service boundary
            logger.info("identity lookup failed: %s", exc)
            self._respond({"error": "lookup failed"})

    def _respond(self, payload: dict) -> None:
        self.request.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, socket_path: Path, mappings: MappingStore, allowed_group: str) -> None:
        self.mappings = mappings
        self.allowed_group = allowed_group
        super().__init__(str(socket_path), _Handler)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-path", type=Path, default=DEFAULT_SOCKET_PATH)
    parser.add_argument("--group", default=DEFAULT_GROUP)
    args = parser.parse_args(argv)

    settings = get_settings()
    args.socket_path.parent.mkdir(parents=True, exist_ok=True)
    args.socket_path.unlink(missing_ok=True)
    server = _Server(args.socket_path, MappingStore(settings.mappings_db_path), args.group)
    args.socket_path.chmod(0o660)
    try:
        os.chown(args.socket_path, -1, grp.getgrnam(args.group).gr_gid)
    except KeyError as exc:
        server.server_close()
        args.socket_path.unlink(missing_ok=True)
        raise SystemExit(f"lookup group does not exist: {args.group}") from exc
    logger.info("identity lookup listening on %s", args.socket_path)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        args.socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
