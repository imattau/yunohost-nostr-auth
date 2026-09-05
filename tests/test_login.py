import json

import pytest
from nostr_sdk import EventBuilder, Keys, Kind, Tag

from yunohost_nostr_auth.auth import login
from yunohost_nostr_auth.auth.challenge import Challenge
from yunohost_nostr_auth.identity.mappings import MappingStore
from yunohost_nostr_auth.ynh import sessions

DOMAIN = "example.org"


def _login_challenge(nonce="nonce-1") -> Challenge:
    return Challenge(nonce=nonce, domain=DOMAIN, action=login.LOGIN_ACTION, issued_at=0, expires_at=10_000_000_000)


def _signed_event(keys: Keys, challenge: Challenge) -> str:
    builder = EventBuilder(Kind(22242), "").tags(
        [
            Tag.parse(["challenge", challenge.nonce]),
            Tag.parse(["domain", challenge.domain]),
            Tag.parse(["action", challenge.action]),
        ]
    )
    return builder.finalize(keys).as_json()


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "identities.db")


def _fake_mint(monkeypatch, capture=None):
    def fake_mint_session(ynh_username, host, **kw):
        if capture is not None:
            capture.append((ynh_username, host))
        return sessions.MintedSession(cookie_name="yunohost.portal", token="the-jwt", max_age=259200)

    monkeypatch.setattr(sessions, "mint_session", fake_mint_session)


def test_authenticate_mints_a_session_for_a_linked_pubkey(store, monkeypatch):
    keys = Keys.generate()
    store.link("matt", keys.public_key().to_hex())
    challenge = _login_challenge()
    calls = []
    _fake_mint(monkeypatch, calls)

    minted = login.authenticate(store, challenge=challenge, event_json=_signed_event(keys, challenge))

    assert minted.token == "the-jwt"
    assert calls == [("matt", DOMAIN)]
    assert store.get_by_username("matt").last_used is not None


def test_authenticate_rejects_unlinked_pubkey(store, monkeypatch):
    keys = Keys.generate()
    challenge = _login_challenge()
    _fake_mint(monkeypatch)

    with pytest.raises(login.LoginError, match="not linked"):
        login.authenticate(store, challenge=challenge, event_json=_signed_event(keys, challenge))


def test_authenticate_requires_a_challenge(store, monkeypatch):
    keys = Keys.generate()
    _fake_mint(monkeypatch)

    with pytest.raises(login.LoginError, match="challenge"):
        login.authenticate(store, challenge=None, event_json=_signed_event(keys, _login_challenge()))


def test_authenticate_rejects_link_action_challenge(store, monkeypatch):
    keys = Keys.generate()
    store.link("matt", keys.public_key().to_hex())
    link_challenge = Challenge(nonce="n", domain=DOMAIN, action="yunohost-link", issued_at=0, expires_at=10_000_000_000)
    _fake_mint(monkeypatch)

    with pytest.raises(login.LoginError, match="yunohost-login"):
        login.authenticate(store, challenge=link_challenge, event_json=_signed_event(keys, link_challenge))


def test_authenticate_rejects_forged_signature(store, monkeypatch):
    keys = Keys.generate()
    other_keys = Keys.generate()
    store.link("matt", keys.public_key().to_hex())
    challenge = _login_challenge()
    _fake_mint(monkeypatch)

    raw = json.loads(_signed_event(keys, challenge))
    raw["pubkey"] = other_keys.public_key().to_hex()

    with pytest.raises(login.LoginError):
        login.authenticate(store, challenge=challenge, event_json=json.dumps(raw))
