import pytest
from nostr_sdk import Keys

from yunohost_nostr_auth.identity.npub import hex_to_npub, npub_to_hex


def test_round_trip():
    keys = Keys.generate()
    hex_pubkey = keys.public_key().to_hex()

    npub = hex_to_npub(hex_pubkey)
    assert npub.startswith("npub1")
    assert npub_to_hex(npub) == hex_pubkey


def test_rejects_hex_passed_as_npub():
    keys = Keys.generate()
    with pytest.raises(ValueError, match="npub1"):
        npub_to_hex(keys.public_key().to_hex())


def test_rejects_garbage():
    with pytest.raises(ValueError):
        npub_to_hex("npub1notreallyanpub")
    with pytest.raises(ValueError):
        hex_to_npub("not-hex")
