from __future__ import annotations

import json
import os
import socket
import threading

from yunohost_nostr_auth.identity.mappings import Identity
from yunohost_nostr_auth.ynh import identity_lookup, identity_lookup_server


PUBKEY = "a" * 64


class _Mappings:
    def __init__(self, identity=None):
        self.identity = identity

    def get_by_pubkey(self, pubkey):
        assert pubkey == PUBKEY
        return self.identity


def _request(socket_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect(str(socket_path))
        sock.sendall(json.dumps(payload).encode() + b"\n")
        return json.loads(sock.recv(4096))


def _start(tmp_path, mappings, monkeypatch):
    monkeypatch.setattr(
        identity_lookup_server.grp,
        "getgrnam",
        lambda name: type("Group", (), {"gr_gid": os.getgid(), "gr_mem": []})(),
    )
    monkeypatch.setattr(
        identity_lookup_server.pwd,
        "getpwuid",
        lambda uid: type("Passwd", (), {"pw_name": "mcp"})(),
    )
    path = tmp_path / "lookup.sock"
    server = identity_lookup_server._Server(path, mappings, "nostr-auth-lookup")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return path, server, thread


def test_lookup_returns_only_link_status_and_username(tmp_path, monkeypatch):
    identity = Identity("codex", PUBKEY, 1, 2, True)
    path, server, thread = _start(tmp_path, _Mappings(identity), monkeypatch)
    try:
        assert _request(path, {"pubkey": PUBKEY}) == {"linked": True, "username": "codex"}
        assert identity_lookup.lookup_identity(PUBKEY, socket_path=path).username == "codex"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_lookup_does_not_enumerate_or_accept_extra_fields(tmp_path, monkeypatch):
    path, server, thread = _start(tmp_path, _Mappings(), monkeypatch)
    try:
        assert _request(path, {"pubkey": PUBKEY}) == {"linked": False, "username": None}
        assert "error" in _request(path, {"pubkey": PUBKEY, "extra": True})
        assert "error" in _request(path, {"pubkey": PUBKEY.upper()})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
