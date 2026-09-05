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


def test_resolves_a_linked_username(app, client):
    app.state.mappings.link("matt", "a" * 64)

    response = client.get("/.well-known/nostr.json", params={"name": "matt"})

    assert response.status_code == 200
    assert response.json() == {"names": {"matt": "a" * 64}}


def test_unlinked_username_resolves_to_nothing(client):
    response = client.get("/.well-known/nostr.json", params={"name": "nobody"})

    assert response.status_code == 200
    assert response.json() == {"names": {}}


def test_missing_name_param_resolves_to_nothing_not_a_full_listing(app, client):
    app.state.mappings.link("matt", "a" * 64)
    app.state.mappings.link("alice", "b" * 64)

    response = client.get("/.well-known/nostr.json")

    assert response.status_code == 200
    assert response.json() == {"names": {}}


def test_response_is_cors_readable(app, client):
    app.state.mappings.link("matt", "a" * 64)

    response = client.get("/.well-known/nostr.json", params={"name": "matt"})

    assert response.headers["access-control-allow-origin"] == "*"
