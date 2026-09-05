import io
import json

from yunohost_nostr_auth.ynh import portal_client


class _FakeResponse:
    def __init__(self, body: dict):
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_get_authenticated_username_forwards_explicit_host_header(monkeypatch):
    """Confirmed on a real install: without an explicit Host header, urllib
    defaults it to the literal 127.0.0.1:6788 address, which makes
    portal-api's own host-binding check (PHASE0_INVESTIGATION.md) reject
    every session as unauthenticated - even a genuinely valid one.
    """
    captured = {}

    def fake_urlopen(request, timeout):
        captured["headers"] = dict(request.header_items())
        return _FakeResponse({"username": "matt"})

    monkeypatch.setattr(portal_client.urllib.request, "urlopen", fake_urlopen)

    username = portal_client.get_authenticated_username(
        "yunohost.portal=x", host="example.org"
    )

    assert username == "matt"
    assert captured["headers"]["Host"] == "example.org"
