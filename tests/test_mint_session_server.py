import json
import os
import socket
import threading

from yunohost_nostr_auth.ynh import ldap_lookup, mint_session_server, portal_cookie


def _start_server(socket_path, allowed_uid):
    server = mint_session_server._Server(socket_path, allowed_uid)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _request(socket_path, payload: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect(str(socket_path))
        sock.sendall(json.dumps(payload).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return json.loads(data)


def test_rejects_connection_from_unexpected_uid(tmp_path):
    socket_path = tmp_path / "mint.sock"
    server, thread = _start_server(socket_path, allowed_uid=os.getuid() + 1)
    try:
        response = _request(socket_path, {"username": "matt", "host": "example.org"})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response == {"error": "forbidden"}


def test_accepts_connection_from_allowed_uid_and_mints(tmp_path, monkeypatch):
    socket_path = tmp_path / "mint.sock"

    monkeypatch.setattr(
        ldap_lookup,
        "get_user_contact_info",
        lambda username: ldap_lookup.UserContactInfo(fullname="Matt Example", email="matt@example.org"),
    )
    monkeypatch.setattr(portal_cookie, "read_session_secret", lambda: "0123456789abcdef0123456789abcdef"[:32])

    session_folder = tmp_path / "sessions"
    session_folder.mkdir()
    monkeypatch.setattr(portal_cookie, "SESSION_FOLDER", session_folder)
    real_mint = portal_cookie.mint

    def patched_mint(**kwargs):
        kwargs.setdefault("session_folder", session_folder)
        return real_mint(**kwargs)

    monkeypatch.setattr(portal_cookie, "mint", patched_mint)

    server, thread = _start_server(socket_path, allowed_uid=os.getuid())
    try:
        response = _request(socket_path, {"username": "matt", "host": "example.org"})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert "token" in response
    assert response["max_age"] == portal_cookie.SESSION_VALIDITY - 600


def test_bad_request_returns_error(tmp_path):
    socket_path = tmp_path / "mint.sock"
    server, thread = _start_server(socket_path, allowed_uid=os.getuid())
    try:
        response = _request(socket_path, {"not": "the right shape"})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert "error" in response
