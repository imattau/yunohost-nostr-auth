# yunohost-nostr-auth

A standalone service that lets an existing YunoHost user authenticate using a
linked Nostr identity (NIP-07 first, NIP-46 later), without replacing
password login or requiring upstream YunoHost changes.

This repo is the core service and protocol implementation. The YunoHost
package that installs and wires it up on a server lives in a sibling repo,
[`nostr_auth_ynh`](https://github.com/imattau/nostr_auth_ynh).

See [PLAN.md](PLAN.md) for the full architecture and phased roadmap.

## Status

Phase 1 investigation done — see [`PHASE0_INVESTIGATION.md`](PHASE0_INVESTIGATION.md).
Short version: there is no password-less login function this service can
call on its own. Minting a `yunohost.portal` session requires the
privileges of the `ynh-portal` system user (to read
`/etc/yunohost/.ssowat_cookie_secret` and write
`/var/cache/yunohost-portal/sessions/`), so session creation has to go
through a narrowly-scoped privileged helper rather than happening in this
daemon's own process. That helper (Phase 2) is the next thing to build.

## Layout

```text
src/yunohost_nostr_auth/
    auth/
        challenge.py     # issue/consume single-use, domain+action-bound challenges
        nostr_verify.py  # NIP-01 event structure + secp256k1/Schnorr signature checks
        session.py        # bridge into YunoHost's own session creation (Phase 1)
    identity/
        mappings.py       # ynh_username <-> nostr pubkey (SQLite)
        linking.py         # link/replace/unlink, gated on an existing YNH session
    ynh/
        users.py           # YunoHost user lookup
        sessions.py        # YunoHost session establishment
        permissions.py     # least-privilege access to the above
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
