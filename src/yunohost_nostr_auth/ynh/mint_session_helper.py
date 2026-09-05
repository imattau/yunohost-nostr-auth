#!/usr/bin/env python3
"""CLI entry point, meant to run as the `ynh-portal` system user (never as
the main yunohost-nostr-auth daemon's own user), invoked over a narrowly
scoped `sudo` rule with no attacker-controlled arguments beyond an already
Nostr-verified `ynh_username` and the request `Host` the browser used.

    yunohost-nostr-auth-mint-session <ynh_username> <host>

Prints `{"token": ..., "session_id": ..., "max_age": ...}` as JSON to
stdout on success (exit 0). On failure, prints a one-line error to stderr
and exits non-zero - never partial/malformed JSON to stdout.

This is the privileged half of ynh/sessions.py's mint_session(); see that
module and PHASE0_INVESTIGATION.md's Conclusions for why session minting
has to cross a privilege boundary at all rather than happening in the main
daemon process.
"""

from __future__ import annotations

import argparse
import json
import sys

from yunohost_nostr_auth.ynh import ldap_lookup, portal_cookie


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ynh_username")
    parser.add_argument("host")
    args = parser.parse_args(argv)

    try:
        contact = ldap_lookup.get_user_contact_info(args.ynh_username)
        secret = portal_cookie.read_session_secret()
        minted = portal_cookie.mint(
            ynh_username=args.ynh_username,
            host=args.host,
            email=contact.email,
            fullname=contact.fullname,
            secret=secret,
        )
    except Exception as e:
        print(f"mint-session failed for {args.ynh_username!r}@{args.host!r}: {e}", file=sys.stderr)
        return 1

    json.dump(
        {"token": minted.token, "session_id": minted.session_id, "max_age": minted.max_age},
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
