"""PLAN.md Phase 13: brute-force throttling relies on nostr_auth_ynh's
fail2ban jail watching a dedicated log file for lines this service emits.
These tests pin the two things that jail actually depends on: the client
IP is taken from X-Real-IP (set by nginx, not attacker-controlled - see
server.py's _client_ip), and a failed login/link/unlink attempt always
produces a "... failure from <ip>: ..." line, so the fail2ban filter's
regex keeps matching.
"""

import json
import logging

import pytest
from nostr_sdk import EventBuilder, Keys, Kind, Tag
from starlette.testclient import TestClient

from yunohost_nostr_auth import server as server_module
from yunohost_nostr_auth.config import Settings
from yunohost_nostr_auth.server import _client_ip, _configure_logging, logger
from yunohost_nostr_auth.ynh import portal_client

DOMAIN = "example.org"


def _sign(keys: Keys, challenge: dict) -> dict:
    builder = EventBuilder(Kind(challenge["kind"]), "").tags(
        [
            Tag.parse(["challenge", challenge["nonce"]]),
            Tag.parse(["domain", challenge["domain"]]),
            Tag.parse(["action", challenge["action"]]),
        ]
    )
    return json.loads(builder.finalize(keys).as_json())


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTR_AUTH_DATA_DIR", str(tmp_path))
    return server_module.create_app()


@pytest.fixture
def client(app):
    return TestClient(app, base_url=f"http://{DOMAIN}")


class _FakeRequest:
    def __init__(self, headers, client_host=None):
        self.headers = headers
        self.client = type("C", (), {"host": client_host})() if client_host else None


def test_client_ip_trusts_x_real_ip_set_by_nginx():
    request = _FakeRequest({"x-real-ip": "203.0.113.7"}, client_host="127.0.0.1")
    assert _client_ip(request) == "203.0.113.7"


def test_client_ip_falls_back_to_transport_address_without_the_header():
    request = _FakeRequest({}, client_host="198.51.100.1")
    assert _client_ip(request) == "198.51.100.1"


def test_client_ip_falls_back_to_unknown_with_neither():
    request = _FakeRequest({})
    assert _client_ip(request) == "unknown"


def test_configure_logging_writes_failures_to_the_security_log(tmp_path):
    log_path = tmp_path / "nostr_auth.log"
    settings = Settings(security_log_path=log_path)

    handlers_before = list(logger.handlers)
    try:
        _configure_logging(settings)
        logger.warning("nostr login failure from 203.0.113.7: this pubkey is not linked")
    finally:
        logger.handlers[:] = handlers_before

    assert "nostr login failure from 203.0.113.7:" in log_path.read_text()


def test_failed_login_logs_the_requesting_ip(client, caplog):
    keys = Keys.generate()
    challenge = client.get("/challenge").json()
    event = _sign(keys, challenge)

    with caplog.at_level(logging.WARNING, logger="yunohost_nostr_auth.server"):
        response = client.post(
            "/authenticate",
            json={"event": event},
            headers={"x-real-ip": "203.0.113.99"},
        )

    assert response.status_code == 401
    assert any(
        "nostr login failure from 203.0.113.99:" in record.message for record in caplog.records
    )


def test_failed_link_logs_the_requesting_ip(client, caplog, monkeypatch):
    keys = Keys.generate()
    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: "matt"
    )
    challenge = client.post("/link/challenge").json()
    # A stale/garbage challenge tag makes this fail linking (LinkingError),
    # which is exactly the brute-force-relevant failure fail2ban wants.
    event = _sign(keys, {**challenge, "nonce": "not-a-real-nonce"})

    with caplog.at_level(logging.WARNING, logger="yunohost_nostr_auth.server"):
        response = client.post(
            "/link",
            json={"event": event},
            headers={"cookie": "yunohost.portal=whatever", "x-real-ip": "203.0.113.55"},
        )

    assert response.status_code == 401
    assert any(
        "identity link failure from 203.0.113.55:" in record.message for record in caplog.records
    )
