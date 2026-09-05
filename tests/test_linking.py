import pytest
from nostr_sdk import EventBuilder, Keys, Kind, Tag

from yunohost_nostr_auth.auth.challenge import Challenge
from yunohost_nostr_auth.identity import linking
from yunohost_nostr_auth.identity.mappings import MappingStore
from yunohost_nostr_auth.ynh import portal_client

DOMAIN = "example.org"


def _link_challenge(nonce="nonce-1", issued_at=0, expires_at=10_000_000_000) -> Challenge:
    return Challenge(
        nonce=nonce, domain=DOMAIN, action=linking.LINK_ACTION, issued_at=issued_at, expires_at=expires_at
    )


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


def _fake_authenticated_as(monkeypatch, username):
    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: username
    )


def test_confirm_and_link_creates_mapping(store, monkeypatch):
    _fake_authenticated_as(monkeypatch, "matt")
    keys = Keys.generate()
    challenge = _link_challenge()

    username = linking.confirm_and_link(
        store,
        cookie_header="yunohost.portal=whatever",
        challenge=challenge,
        event_json=_signed_event(keys, challenge),
    )

    assert username == "matt"
    assert store.get_by_username("matt").pubkey == keys.public_key().to_hex()


def test_confirm_and_link_requires_a_challenge(store, monkeypatch):
    _fake_authenticated_as(monkeypatch, "matt")
    keys = Keys.generate()

    with pytest.raises(linking.LinkingError, match="challenge"):
        linking.confirm_and_link(
            store,
            cookie_header="yunohost.portal=whatever",
            challenge=None,
            event_json=_signed_event(keys, _link_challenge()),
        )


def test_confirm_and_link_rejects_wrong_action_challenge(store, monkeypatch):
    _fake_authenticated_as(monkeypatch, "matt")
    keys = Keys.generate()
    login_challenge = Challenge(
        nonce="n", domain=DOMAIN, action="yunohost-login", issued_at=0, expires_at=10_000_000_000
    )

    with pytest.raises(linking.LinkingError, match="yunohost-link"):
        linking.confirm_and_link(
            store,
            cookie_header="yunohost.portal=whatever",
            challenge=login_challenge,
            event_json=_signed_event(keys, login_challenge),
        )


def test_confirm_and_link_rejects_unauthenticated_session(store, monkeypatch):
    def _raise(cookie_header, **kw):
        raise portal_client.PortalAuthError("nope")

    monkeypatch.setattr(portal_client, "get_authenticated_username", _raise)
    keys = Keys.generate()
    challenge = _link_challenge()

    with pytest.raises(linking.LinkingError, match="not currently logged in"):
        linking.confirm_and_link(
            store,
            cookie_header="yunohost.portal=bad",
            challenge=challenge,
            event_json=_signed_event(keys, challenge),
        )


def test_confirm_and_link_rejects_forged_signature(store, monkeypatch):
    _fake_authenticated_as(monkeypatch, "matt")
    keys = Keys.generate()
    other_keys = Keys.generate()
    challenge = _link_challenge()

    # Sign with `keys` but claim `other_keys`'s pubkey.
    import json

    raw = json.loads(_signed_event(keys, challenge))
    raw["pubkey"] = other_keys.public_key().to_hex()

    with pytest.raises(linking.LinkingError):
        linking.confirm_and_link(
            store,
            cookie_header="yunohost.portal=whatever",
            challenge=challenge,
            event_json=json.dumps(raw),
        )


def test_confirm_and_unlink(store, monkeypatch):
    store.link("matt", "a" * 64)
    _fake_authenticated_as(monkeypatch, "matt")

    username = linking.confirm_and_unlink(store, cookie_header="yunohost.portal=whatever")

    assert username == "matt"
    assert store.get_by_username("matt") is None


def test_confirm_and_unlink_rejects_unauthenticated_session(store, monkeypatch):
    def _raise(cookie_header, **kw):
        raise portal_client.PortalAuthError("nope")

    monkeypatch.setattr(portal_client, "get_authenticated_username", _raise)

    with pytest.raises(linking.LinkingError, match="not currently logged in"):
        linking.confirm_and_unlink(store, cookie_header="yunohost.portal=bad")
