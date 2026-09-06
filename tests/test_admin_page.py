import pytest
from starlette.testclient import TestClient

from yunohost_nostr_auth import server as server_module
from yunohost_nostr_auth.ynh import portal_client

DOMAIN = "example.org"
COOKIE = "yunohost.portal=whatever"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTR_AUTH_DATA_DIR", str(tmp_path))
    return server_module.create_app()


@pytest.fixture
def client(app):
    return TestClient(app, base_url=f"http://{DOMAIN}")


def _as_admin(monkeypatch, username="root-admin"):
    monkeypatch.setattr(
        portal_client,
        "get_authenticated_session",
        lambda cookie_header, **kw: portal_client.AuthenticatedSession(
            username=username, groups=["admins"]
        ),
    )


def _as_non_admin(monkeypatch, username="matt"):
    monkeypatch.setattr(
        portal_client,
        "get_authenticated_session",
        lambda cookie_header, **kw: portal_client.AuthenticatedSession(
            username=username, groups=["visitors"]
        ),
    )


def test_admin_page_served_with_csp(client):
    response = client.get("/nostr-admin")
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    assert "Nostr Identities" in response.text


def test_admin_session_reports_unauthenticated_without_cookie(client):
    response = client.get("/admin/api/session")
    assert response.status_code == 200
    assert response.json() == {"authenticated": False, "is_admin": False}


def test_admin_session_reports_non_admin(client, monkeypatch):
    _as_non_admin(monkeypatch)
    response = client.get("/admin/api/session", headers={"cookie": COOKIE})
    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["is_admin"] is False


def test_admin_session_reports_admin(client, monkeypatch):
    _as_admin(monkeypatch)
    response = client.get("/admin/api/session", headers={"cookie": COOKIE})
    assert response.json() == {"authenticated": True, "is_admin": True, "username": "root-admin"}


def test_admin_endpoints_reject_non_admin(client, monkeypatch):
    _as_non_admin(monkeypatch)
    response = client.get("/admin/api/identities", headers={"cookie": COOKIE})
    assert response.status_code == 403


def test_admin_endpoints_reject_missing_cookie(client):
    response = client.get("/admin/api/identities")
    assert response.status_code == 401


def test_admin_can_list_identities_across_users(client, monkeypatch, app):
    _as_admin(monkeypatch)
    app.state.mappings.add_identity("matt", "a" * 64, signer_type="nip07", linked_by="self-service")
    app.state.mappings.add_identity("alice", "b" * 64, signer_type="passkey", linked_by="self-service")

    response = client.get("/admin/api/identities", headers={"cookie": COOKIE})

    assert response.status_code == 200
    usernames = {identity["username"] for identity in response.json()["identities"]}
    assert usernames == {"matt", "alice"}


def test_admin_can_add_identity_for_any_user(client, monkeypatch):
    _as_admin(monkeypatch)
    pubkey = "c" * 64

    response = client.post(
        "/admin/api/identities",
        headers={"cookie": COOKIE},
        json={"username": "agentuser", "pubkey": pubkey, "signer_type": "unknown", "label": "Agent key"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["identity"]["username"] == "agentuser"
    assert body["identity"]["pubkey"] == pubkey
    assert body["identity"]["label"] == "Agent key"


def test_admin_add_identity_rejects_pubkey_already_linked_elsewhere(client, monkeypatch, app):
    _as_admin(monkeypatch)
    pubkey = "d" * 64
    app.state.mappings.add_identity("matt", pubkey)

    response = client.post(
        "/admin/api/identities",
        headers={"cookie": COOKIE},
        json={"username": "alice", "pubkey": pubkey},
    )

    assert response.status_code == 409


def test_admin_can_revoke_identity(client, monkeypatch, app):
    _as_admin(monkeypatch)
    identity = app.state.mappings.add_identity("matt", "e" * 64)

    response = client.post(
        f"/admin/api/identities/{identity.identity_id}/revoke",
        headers={"cookie": COOKIE},
        json={"username": "matt"},
    )

    assert response.status_code == 200
    assert app.state.mappings.get_by_id(identity.identity_id).enabled is False


def test_admin_revoke_wrong_username_is_not_found(client, monkeypatch, app):
    _as_admin(monkeypatch)
    identity = app.state.mappings.add_identity("matt", "f" * 64)

    response = client.post(
        f"/admin/api/identities/{identity.identity_id}/revoke",
        headers={"cookie": COOKIE},
        json={"username": "someone-else"},
    )

    assert response.status_code == 404


def test_admin_can_rename_identity(client, monkeypatch, app):
    _as_admin(monkeypatch)
    identity = app.state.mappings.add_identity("matt", "1" * 64)

    response = client.post(
        f"/admin/api/identities/{identity.identity_id}/rename",
        headers={"cookie": COOKIE},
        json={"username": "matt", "label": "Main laptop"},
    )

    assert response.status_code == 200
    assert response.json()["identity"]["label"] == "Main laptop"


def test_admin_can_unlink_all_identities_for_a_user(client, monkeypatch, app):
    _as_admin(monkeypatch)
    app.state.mappings.add_identity("matt", "2" * 64)
    app.state.mappings.add_identity("matt", "3" * 64)

    response = client.post(
        "/admin/api/identities/unlink",
        headers={"cookie": COOKIE},
        json={"username": "matt"},
    )

    assert response.status_code == 200
    assert app.state.mappings.list_by_username("matt") == []
