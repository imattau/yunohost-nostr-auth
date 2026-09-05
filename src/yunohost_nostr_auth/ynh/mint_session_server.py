"""Long-running privileged session-minting server.

PHASE0_INVESTIGATION.md originally proposed a `sudo -u ynh-portal` helper
spawned per request. Confirmed on a real (containerized) YunoHost install:
that never works there - the container itself sets the kernel's
"no new privileges" bit, which permanently blocks *any* process from
gaining privilege via execve of a setuid binary (sudo included),
regardless of what our own systemd unit or sudoers rule allow. See
PHASE0_INVESTIGATION.md's "Privilege-drop redesign" section.

The fix: don't gain privilege at request time at all. This process runs as
its own separate systemd service with `User=ynh-portal` from the start -
systemd (running as root) forks and drops to ynh-portal the same way it
would for any service, which is a privilege *drop* made by an
already-privileged supervisor, not a privilege *gain* by this process
itself, so it's unaffected by no_new_privs. The main (unprivileged) daemon
then just asks this always-running process over a Unix socket, instead of
spawning anything.

Since the socket's filesystem permissions alone can't restrict who
connects without extra group wrangling across two different app users,
every connection's SO_PEERCRED is checked against the main daemon's own
uid (resolved once at startup from --allowed-user) - anything else is
rejected before ever touching the LDAP lookup or the cookie secret.
"""

from __future__ import annotations

import argparse
import json
import logging
import pwd
import socket
import socketserver
import struct
from pathlib import Path

from yunohost_nostr_auth.ynh import ldap_lookup, portal_cookie

logger = logging.getLogger("yunohost_nostr_auth.mint_session_server")

DEFAULT_SOCKET_PATH = Path("/run/nostr_auth-mint/mint.sock")
_UCRED_FORMAT = "3i"  # struct ucred { pid_t pid; uid_t uid; gid_t gid; } on Linux


def _peer_uid(conn: socket.socket) -> int:
    creds = conn.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize(_UCRED_FORMAT)
    )
    _pid, uid, _gid = struct.unpack(_UCRED_FORMAT, creds)
    return uid


def _read_line(conn: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


class _Handler(socketserver.BaseRequestHandler):
    server: "_Server"

    def handle(self) -> None:
        conn: socket.socket = self.request

        try:
            uid = _peer_uid(conn)
        except OSError as e:
            logger.warning("could not read peer credentials: %s", e)
            return

        if uid != self.server.allowed_uid:
            logger.warning("rejected connection from unexpected uid %s", uid)
            conn.sendall(json.dumps({"error": "forbidden"}).encode() + b"\n")
            return

        try:
            request = json.loads(_read_line(conn))
            username = request["username"]
            host = request["host"]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            conn.sendall(json.dumps({"error": f"bad request: {e}"}).encode() + b"\n")
            return

        try:
            contact = ldap_lookup.get_user_contact_info(username)
            secret = portal_cookie.read_session_secret()
            minted = portal_cookie.mint(
                ynh_username=username,
                host=host,
                email=contact.email,
                fullname=contact.fullname,
                secret=secret,
            )
        except Exception as e:
            logger.info("mint-session failed for %r@%r: %s", username, host, e)
            conn.sendall(json.dumps({"error": str(e)}).encode() + b"\n")
            return

        conn.sendall(
            json.dumps(
                {
                    "token": minted.token,
                    "session_id": minted.session_id,
                    "max_age": minted.max_age,
                }
            ).encode()
            + b"\n"
        )


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, socket_path: Path, allowed_uid: int) -> None:
        self.allowed_uid = allowed_uid
        super().__init__(str(socket_path), _Handler)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket-path", type=Path, default=DEFAULT_SOCKET_PATH)
    parser.add_argument(
        "--allowed-user",
        required=True,
        help="system username of the main (unprivileged) daemon - the only uid allowed to connect",
    )
    args = parser.parse_args(argv)

    allowed_uid = pwd.getpwnam(args.allowed_user).pw_uid

    args.socket_path.parent.mkdir(parents=True, exist_ok=True)
    args.socket_path.unlink(missing_ok=True)

    server = _Server(args.socket_path, allowed_uid)
    # World-connectable at the filesystem level - real authorization is the
    # SO_PEERCRED check in _Handler.handle(), not this mode bit.
    args.socket_path.chmod(0o666)

    logger.info("listening on %s, accepting only uid %s", args.socket_path, allowed_uid)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        args.socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
