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


def test_login_page_serves_html_with_strict_csp(client):
    response = client.get("/nostr-login")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert "'unsafe-inline'" not in response.headers["content-security-policy"].split("script-src")[1].split(";")[0]
    assert "<noscript>" in response.text
    assert '<script src="/static/nostr-login-page.js"></script>' in response.text
    assert "<script>" not in response.text  # PLAN.md Phase 13: no inline script, strict CSP


def test_login_page_references_the_real_api_endpoints(client):
    response = client.get("/static/nostr-login-page.js")

    assert "window.nostr" in response.text
    assert "/challenge" in response.text
    assert "/authenticate" in response.text
