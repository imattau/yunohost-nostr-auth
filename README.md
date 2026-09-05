# yunohost-nostr-auth

A standalone service that lets an existing YunoHost user authenticate using a
linked Nostr identity (NIP-07 first, NIP-46 later), without replacing
password login or requiring upstream YunoHost changes.

This repo is the core service and protocol implementation. The YunoHost
package that installs and wires it up on a server lives in a sibling repo,
[`nostr_auth_ynh`](https://github.com/imattau/nostr_auth_ynh).

See [PLAN.md](PLAN.md) for the full architecture and phased roadmap.

## Status

Phase 1 (session-creation investigation) and Phase 2 (the core service:
challenges, signature verification, identity mapping, linking, and the
HTTP endpoints) are implemented and tested. See
[`PHASE0_INVESTIGATION.md`](PHASE0_INVESTIGATION.md) for the session-format
findings this is built against.

Short version of the one architectural wrinkle: there is no password-less
login function YunoHost exposes. Minting a `yunohost.portal` session
requires the privileges of the `ynh-portal` system user (to read
`/etc/yunohost/.ssowat_cookie_secret` and write
`/var/cache/yunohost-portal/sessions/`), so session minting happens in a
separate, narrowly-scoped helper (`ynh/mint_session_helper.py`) invoked via
`sudo -u ynh-portal`, never in this daemon's own process. That helper's
crypto is unit-tested here, but the helper itself, the sudoers rule, and
the LDAP anonymous-bind assumption it relies on are **not yet verified
against a live YunoHost 12 install** — that's the next real milestone
(`nostr_auth_ynh`'s packaging + a test install).

## Layout

```text
src/yunohost_nostr_auth/
    server.py              # the ASGI app: GET/POST routes wiring everything below together
    config.py              # NOSTR_AUTH_* environment settings
    auth/
        challenge.py       # issue/consume single-use, domain+action-bound challenges
        nostr_verify.py    # NIP-01 event verification (via nostr-sdk) + challenge binding
        login.py           # challenge + signature + pubkey->account -> mint a session
        session.py         # the unprivileged side of "mint a session" - delegates to ynh/sessions.py
    identity/
        npub.py            # npub <-> hex, at the UI boundary only
        mappings.py        # ynh_username <-> nostr pubkey (SQLite)
        linking.py         # link/unlink, gated on an existing YNH session + a fresh signature
    ynh/
        portal_client.py       # unprivileged: "who is this cookie", via the real portal-api's /me
        permissions.py         # documents the privilege boundary below
        sessions.py             # unprivileged: shells out to the helper below via sudo
        mint_session_helper.py  # privileged (runs as ynh-portal): the actual sudo entry point
        portal_cookie.py        # privileged: reproduces YunoHost's JWT + session-file format
        ldap_lookup.py          # privileged: anonymous LDAP bind for cn/mail lookup
```

## Development

```bash
uv sync
uv run pytest
```

## First milestone

```text
Existing YunoHost user "matt" has linked pubkey X
→ open /nostr-login
→ click Sign in with Nostr
→ approve NIP-07 signature
→ arrive at normal YunoHost portal
→ open an SSO-protected app
→ app recognises "matt"
```

without modifying SSOwat or replacing core YunoHost files.
