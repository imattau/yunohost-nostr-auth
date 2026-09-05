import pytest

from yunohost_nostr_auth.identity.mappings import MappingStore, PubkeyAlreadyLinked

PUBKEY_A = "a" * 64
PUBKEY_B = "b" * 64


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "identities.db")


def test_link_then_lookup(store):
    store.link("matt", PUBKEY_A)

    identity = store.get_by_pubkey(PUBKEY_A)
    assert identity is not None
    assert identity.ynh_username == "matt"
    assert identity.enabled

    assert store.get_by_username("matt").pubkey == PUBKEY_A


def test_unknown_pubkey_returns_none(store):
    assert store.get_by_pubkey(PUBKEY_A) is None
    assert store.get_by_username("matt") is None


def test_replacing_own_identity_is_allowed(store):
    store.link("matt", PUBKEY_A)
    store.link("matt", PUBKEY_B)

    assert store.get_by_pubkey(PUBKEY_A) is None
    assert store.get_by_pubkey(PUBKEY_B).ynh_username == "matt"


def test_pubkey_cannot_be_claimed_by_a_second_user(store):
    store.link("matt", PUBKEY_A)

    with pytest.raises(PubkeyAlreadyLinked):
        store.link("alice", PUBKEY_A)

    # Original mapping is untouched.
    assert store.get_by_pubkey(PUBKEY_A).ynh_username == "matt"


def test_unlink_removes_mapping(store):
    store.link("matt", PUBKEY_A)
    store.unlink("matt")

    assert store.get_by_pubkey(PUBKEY_A) is None
    assert store.get_by_username("matt") is None


def test_touch_last_used(store):
    store.link("matt", PUBKEY_A)
    assert store.get_by_username("matt").last_used is None

    store.touch_last_used("matt")
    assert store.get_by_username("matt").last_used is not None


def test_list_all(store):
    store.link("matt", PUBKEY_A)
    store.link("alice", PUBKEY_B)

    usernames = [identity.ynh_username for identity in store.list_all()]
    assert usernames == ["alice", "matt"]


def test_reopening_store_persists_data(tmp_path):
    db_path = tmp_path / "identities.db"
    MappingStore(db_path).link("matt", PUBKEY_A)

    reopened = MappingStore(db_path)
    assert reopened.get_by_username("matt").pubkey == PUBKEY_A
