from nostr_sdk import Keys

import pytest

from yunohost_nostr_auth import admin_cli
from yunohost_nostr_auth.identity import npub


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTR_AUTH_DATA_DIR", str(tmp_path))
    return tmp_path


def test_link_with_hex_pubkey(data_dir, capsys):
    keys = Keys.generate()
    hex_pubkey = keys.public_key().to_hex()

    exit_code = admin_cli.main(["link", "agent-1", hex_pubkey])

    assert exit_code == 0
    assert hex_pubkey in capsys.readouterr().out


def test_link_with_npub(data_dir, capsys):
    keys = Keys.generate()
    hex_pubkey = keys.public_key().to_hex()
    an_npub = npub.hex_to_npub(hex_pubkey)

    exit_code = admin_cli.main(["link", "agent-2", an_npub])

    assert exit_code == 0
    assert hex_pubkey in capsys.readouterr().out


def test_link_does_not_require_a_live_signature(data_dir):
    # The whole point: an admin can link a pubkey the account holder
    # reported, without that key ever signing anything - unlike the
    # self-service /nostr-account flow (identity/linking.py).
    keys = Keys.generate()
    exit_code = admin_cli.main(["link", "agent-3", keys.public_key().to_hex()])
    assert exit_code == 0


def test_link_rejects_garbage_pubkey(data_dir, capsys):
    exit_code = admin_cli.main(["link", "agent-4", "not-a-real-key"])

    assert exit_code == 1
    assert "error" in capsys.readouterr().err


def test_link_rejects_pubkey_already_linked_to_another_user(data_dir, capsys):
    keys = Keys.generate()
    hex_pubkey = keys.public_key().to_hex()
    admin_cli.main(["link", "agent-5", hex_pubkey])

    exit_code = admin_cli.main(["link", "agent-6", hex_pubkey])

    assert exit_code == 1
    assert "already linked" in capsys.readouterr().err


def test_unlink_removes_the_identity(data_dir):
    keys = Keys.generate()
    admin_cli.main(["link", "agent-7", keys.public_key().to_hex()])

    exit_code = admin_cli.main(["unlink", "agent-7"])

    assert exit_code == 0
    assert admin_cli.main(["list"]) == 0


def test_unlink_unlinked_user_is_a_no_op(data_dir, capsys):
    exit_code = admin_cli.main(["unlink", "nobody"])

    assert exit_code == 0
    assert "nothing to do" in capsys.readouterr().out


def test_list_reports_no_identities_when_empty(data_dir, capsys):
    admin_cli.main(["list"])

    assert "no identities linked" in capsys.readouterr().out


def test_list_reports_linked_identities(data_dir, capsys):
    keys = Keys.generate()
    hex_pubkey = keys.public_key().to_hex()
    admin_cli.main(["link", "agent-8", hex_pubkey])

    admin_cli.main(["list"])

    out = capsys.readouterr().out
    assert "agent-8" in out
    assert hex_pubkey in out
