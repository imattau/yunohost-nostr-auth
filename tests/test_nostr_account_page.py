from starlette.testclient import TestClient

from yunohost_nostr_auth import server as server_module
from yunohost_nostr_auth.web.page import CONTENT_SECURITY_POLICY

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTR_AUTH_DATA_DIR", str(tmp_path))
    return server_module.create_app()


@pytest.fixture
def client(app):
    return TestClient(app, base_url="http://example.org")


def test_account_page_serves_html_with_strict_csp(client):
    response = client.get("/nostr-account")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert "window.nostr" in response.text
    assert "<noscript>" in response.text


def test_account_page_references_the_real_api_endpoints(client):
    response = client.get("/nostr-account")

    assert "/identity" in response.text
    assert "/link/challenge" in response.text
    assert "/link" in response.text
    assert "/unlink" in response.text
