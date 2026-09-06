from starlette.testclient import TestClient

from yunohost_nostr_auth import server as server_module

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTR_AUTH_DATA_DIR", str(tmp_path))
    return server_module.create_app()


@pytest.fixture
def client(app):
    return TestClient(app, base_url="http://example.org")


def test_vendor_bundle_is_served(client):
    response = client.get("/static/nostr-connect-vendor.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")


def test_passkey_bundle_is_served(client):
    response = client.get("/static/nostr-passkey-vendor.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    assert "NostrPasskey" in response.text
    assert len(response.content) > 10_000  # a real bundle, not an empty/placeholder file


def test_ui_helper_is_served(client):
    response = client.get("/static/nostr-connect-ui.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    assert "NostrConnectUI" in response.text


def test_login_page_script_is_served(client):
    response = client.get("/static/nostr-login-page.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    assert "signInWithNip07" in response.text


def test_account_page_script_is_served(client):
    response = client.get("/static/nostr-account-page.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    assert "performLink" in response.text


def test_admin_page_script_is_served(client):
    response = client.get("/static/nostr-admin-page.js")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    assert "loadIdentities" in response.text


def test_unknown_static_asset_is_404(client):
    response = client.get("/static/does-not-exist.js")

    assert response.status_code == 404


def test_path_traversal_is_rejected(client):
    response = client.get("/static/..%2Fserver.py")

    assert response.status_code == 404
