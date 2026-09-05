# yunohost-nostr-auth

A standalone service that lets an existing YunoHost user authenticate using a
linked Nostr identity (NIP-07 first, NIP-46 later), without replacing
password login or requiring upstream YunoHost changes.

This repo is the core service and protocol implementation. The YunoHost
package that installs and wires it up on a server lives in a sibling repo,
[`nostr_auth_ynh`](https://github.com/imattau/nostr_auth_ynh).

See [PLAN.md](PLAN.md) for the full architecture and phased roadmap.

## Status

Phase 0/1: reverse-engineering YunoHost 12's portal API and SSOwat session
creation before writing any authentication code. Findings will land in
`PHASE0_INVESTIGATION.md` (see PLAN.md's Phase 1 for the exact questions
being answered).

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
