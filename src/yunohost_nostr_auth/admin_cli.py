"""Admin-provisioned identity linking (PLAN.md Phase 14's admin interface,
plus the deliberate relaxation of Phase 5 this needs: an admin can bind a
pubkey to an account without a live signature proving possession of it).

This is for provisioning an account on someone/something else's behalf -
most concretely, giving an agent its own YunoHost account using an npub it
reports itself, where there's no browser in the loop to sign a linking
challenge. The self-service flow (/nostr-account, `identity/linking.py`)
remains the right choice whenever the account holder can link themselves;
this is strictly an admin-authority alternative, not a replacement.

Invoked from nostr_auth_ynh's scripts/config (a YunoHost config-panel
action - see that repo's config_panel.toml), which is itself only
reachable by someone who can already administer this YunoHost server, so
no separate authentication happens here - reaching this CLI at all *is*
the admin authority being exercised. Talks directly to the same SQLite
mapping DB the running service reads (NOSTR_AUTH_DATA_DIR), no HTTP
involved.
"""

from __future__ import annotations

import argparse
import sys

from yunohost_nostr_auth.config import get_settings
from yunohost_nostr_auth.identity import npub
from yunohost_nostr_auth.identity.mappings import Identity, MappingStore, PubkeyAlreadyLinked


def _format_identity(identity: Identity) -> str:
    last_used = "never" if identity.last_used is None else str(identity.last_used)
    return (
        f"{identity.ynh_username}: {npub.hex_to_npub(identity.pubkey)} "
        f"({identity.pubkey}) - linked {identity.created_at}, last used {last_used}"
    )


def _link(mappings: MappingStore, username: str, pubkey_or_npub: str) -> int:
    if not username:
        print("error: username is required", file=sys.stderr)
        return 1
    if not pubkey_or_npub:
        print("error: a Nostr public key (npub or hex) is required", file=sys.stderr)
        return 1

    try:
        pubkey_hex = npub.parse_to_hex(pubkey_or_npub)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        mappings.link(username, pubkey_hex)
    except PubkeyAlreadyLinked as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"linked {username} to {npub.hex_to_npub(pubkey_hex)} ({pubkey_hex})")
    return 0


def _unlink(mappings: MappingStore, username: str) -> int:
    if not username:
        print("error: username is required", file=sys.stderr)
        return 1

    if mappings.get_by_username(username) is None:
        print(f"{username} has no linked identity - nothing to do")
        return 0

    mappings.unlink(username)
    print(f"unlinked {username}")
    return 0


def _list(mappings: MappingStore) -> int:
    identities = mappings.list_all()
    if not identities:
        print("no identities linked")
        return 0

    for identity in identities:
        print(_format_identity(identity))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="yunohost-nostr-auth-admin",
        description="Admin-provisioned Nostr identity linking - see admin_cli.py's module docstring.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    link_parser = subparsers.add_parser("link", help="Link a pubkey to a YunoHost account")
    link_parser.add_argument("username")
    link_parser.add_argument("pubkey_or_npub")

    unlink_parser = subparsers.add_parser("unlink", help="Unlink whatever is linked to an account")
    unlink_parser.add_argument("username")

    subparsers.add_parser("list", help="List all linked identities")

    args = parser.parse_args(argv)

    mappings = MappingStore(get_settings().mappings_db_path)

    if args.command == "link":
        return _link(mappings, args.username, args.pubkey_or_npub)
    if args.command == "unlink":
        return _unlink(mappings, args.username)
    return _list(mappings)


if __name__ == "__main__":
    sys.exit(main())
