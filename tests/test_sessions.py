import json
import socket
import threading

import pytest

from yunohost_nostr_auth.ynh import sessions


def _serve_once(socket_path, response: bytes, expected_request: dict | None = None):
    server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock.bind(str(socket_path))
    server_sock.listen(1)

    def _run():
        conn, _ = server_sock.accept()
        with conn:
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            if expected_request is not None:
                assert json.loads(data) == expected_request
            conn.sendall(response)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return server_sock, thread


def test_mint_session_success(tmp_path):
    socket_path = tmp_path / "mint.sock"
    response = json.dumps({"token": "the-jwt", "session_id": "abc", "max_age": 259200}).encode() + b"\n"
    server_sock, thread = _serve_once(
        socket_path, response, expected_request={"username": "matt", "host": "example.org"}
    )
    try:
        minted = sessions.mint_session("matt", "example.org", socket_path=socket_path)
    finally:
        server_sock.close()
        thread.join(timeout=1)

    assert minted.token == "the-jwt"
    assert minted.max_age == 259200
    assert minted.cookie_name == "yunohost.portal"


def test_mint_session_raises_on_error_response(tmp_path):
    socket_path = tmp_path / "mint.sock"
    response = json.dumps({"error": "user not found"}).encode() + b"\n"
    server_sock, thread = _serve_once(socket_path, response)
    try:
        with pytest.raises(sessions.SessionMintError, match="user not found"):
            sessions.mint_session("matt", "example.org", socket_path=socket_path)
    finally:
        server_sock.close()
        thread.join(timeout=1)


def test_mint_session_raises_on_garbage_response(tmp_path):
    socket_path = tmp_path / "mint.sock"
    server_sock, thread = _serve_once(socket_path, b"not json\n")
    try:
        with pytest.raises(sessions.SessionMintError):
            sessions.mint_session("matt", "example.org", socket_path=socket_path)
    finally:
        server_sock.close()
        thread.join(timeout=1)


def test_mint_session_raises_when_socket_does_not_exist(tmp_path):
    with pytest.raises(sessions.SessionMintError):
        sessions.mint_session("matt", "example.org", socket_path=tmp_path / "does-not-exist.sock")
