import json
import subprocess

import pytest

from yunohost_nostr_auth.ynh import sessions


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_mint_session_success(monkeypatch):
    def fake_run(cmd, **kwargs):
        assert cmd[:4] == ["sudo", "-n", "-u", "ynh-portal"]
        assert cmd[-2:] == ["matt", "example.org"]
        return _FakeCompletedProcess(
            returncode=0,
            stdout=json.dumps({"token": "the-jwt", "session_id": "abc", "max_age": 259200}).encode(),
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    minted = sessions.mint_session("matt", "example.org")

    assert minted.token == "the-jwt"
    assert minted.max_age == 259200
    assert minted.cookie_name == "yunohost.portal"


def test_mint_session_raises_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **kwargs: _FakeCompletedProcess(returncode=1, stderr=b"user not found"),
    )

    with pytest.raises(sessions.SessionMintError, match="user not found"):
        sessions.mint_session("matt", "example.org")


def test_mint_session_raises_on_garbage_stdout(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **kwargs: _FakeCompletedProcess(returncode=0, stdout=b"not json")
    )

    with pytest.raises(sessions.SessionMintError):
        sessions.mint_session("matt", "example.org")


def test_mint_session_raises_when_sudo_is_missing(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("sudo not found")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(sessions.SessionMintError):
        sessions.mint_session("matt", "example.org")
