import json

import pytest
from nostr_sdk import EventBuilder, Keys, Kind, Tag
from starlette.testclient import TestClient

from yunohost_nostr_auth import server as server_module
from yunohost_nostr_auth.ynh import portal_client, sessions

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


def test_root_redirects_to_login_page(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/nostr-login"


def test_root_redirects_already_logged_in_user_to_portal(client, monkeypatch):
    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: "matt"
    )

    response = client.get(
        "/", headers={"cookie": "yunohost.portal=whatever"}, follow_redirects=False
    )

    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/yunohost/sso/"


def test_root_redirects_invalid_cookie_to_login_page(client, monkeypatch):
    def _reject(cookie_header, **kw):
        raise portal_client.PortalAuthError("expired")

    monkeypatch.setattr(portal_client, "get_authenticated_username", _reject)

    response = client.get(
        "/", headers={"cookie": "yunohost.portal=stale"}, follow_redirects=False
    )

    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/nostr-login"


def test_full_login_flow(app, client, monkeypatch):
    keys = Keys.generate()
    app.state.mappings.link("matt", keys.public_key().to_hex())

    monkeypatch.setattr(
        sessions,
        "mint_session",
        lambda username, host, **kw: sessions.MintedSession(
            cookie_name="yunohost.portal", token="the-jwt", max_age=259200
        ),
    )

    challenge = client.get("/challenge").json()
    assert challenge["domain"] == DOMAIN
    assert challenge["action"] == "yunohost-login"

    event = _sign(keys, challenge)
    response = client.post("/authenticate", json={"event": event})

    assert response.status_code == 200, response.text
    assert response.json() == {"ok": True}
    assert response.cookies["yunohost.portal"] == "the-jwt"


def test_login_rejects_unlinked_pubkey(client):
    keys = Keys.generate()
    challenge = client.get("/challenge").json()
    event = _sign(keys, challenge)

    response = client.post("/authenticate", json={"event": event})

    assert response.status_code == 401


def test_login_rejects_replayed_challenge(app, client, monkeypatch):
    keys = Keys.generate()
    app.state.mappings.link("matt", keys.public_key().to_hex())
    monkeypatch.setattr(
        sessions,
        "mint_session",
        lambda username, host, **kw: sessions.MintedSession(
            cookie_name="yunohost.portal", token="the-jwt", max_age=259200
        ),
    )

    challenge = client.get("/challenge").json()
    event = _sign(keys, challenge)

    first = client.post("/authenticate", json={"event": event})
    assert first.status_code == 200

    second = client.post("/authenticate", json={"event": event})
    assert second.status_code == 401


def test_authenticate_requires_json_content_type(client):
    response = client.post("/authenticate", content=b"event=whatever")
    assert response.status_code == 415


def test_link_flow_requires_authenticated_cookie(app, client, monkeypatch):
    keys = Keys.generate()

    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: "matt"
    )

    challenge = client.post("/link/challenge").json()
    assert challenge["action"] == "yunohost-link"

    event = _sign(keys, challenge)
    response = client.post(
        "/link",
        json={"event": event, "signer_type": "passkey", "label": "Laptop"},
        headers={"cookie": "yunohost.portal=whatever"},
    )

    assert response.status_code == 200, response.text
    identity = app.state.mappings.get_by_username("matt")
    assert identity.pubkey == keys.public_key().to_hex()
    assert identity.signer_type == "passkey"
    assert identity.label == "Laptop"


def test_link_without_cookie_is_rejected(client):
    keys = Keys.generate()
    challenge = client.post("/link/challenge").json()
    event = _sign(keys, challenge)

    response = client.post("/link", json={"event": event})

    assert response.status_code == 401


def test_unlink_flow(app, client, monkeypatch):
    app.state.mappings.link("matt", "a" * 64)
    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: "matt"
    )

    response = client.post("/unlink", headers={"cookie": "yunohost.portal=whatever"})

    assert response.status_code == 200
    assert app.state.mappings.get_by_username("matt") is None


def test_identity_endpoint_reports_linked_state(app, client, monkeypatch):
    app.state.mappings.link("matt", "a" * 64)
    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: "matt"
    )

    response = client.get("/identity", headers={"cookie": "yunohost.portal=whatever"})

    assert response.status_code == 200
    body = response.json()
    assert body["linked"] is True
    assert body["username"] == "matt"


def test_identity_endpoint_reports_unlinked_when_only_identity_is_revoked(app, client, monkeypatch):
    app.state.mappings.link("matt", "a" * 64)
    identity_id = app.state.mappings.get_by_username("matt").identity_id
    app.state.mappings.revoke_identity(identity_id, "matt")
    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: "matt"
    )

    response = client.get("/identity", headers={"cookie": "yunohost.portal=whatever"})

    assert response.status_code == 200
    assert response.json() == {"linked": False}


def test_identity_endpoint_unlinked(app, client, monkeypatch):
    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: "alice"
    )

    response = client.get("/identity", headers={"cookie": "yunohost.portal=whatever"})

    assert response.status_code == 200
    assert response.json() == {"linked": False}
