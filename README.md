# yunohost-nostr-auth

A standalone service that lets an existing YunoHost user authenticate using a
linked Nostr identity (NIP-07, NIP-46, or passkey), without replacing
password login or requiring upstream YunoHost changes.

This repo is the core service and protocol implementation. The YunoHost
package that installs and wires it up on a server lives in a sibling repo,
[`nostr_auth_ynh`](https://github.com/imattau/nostr_auth_ynh).

See [PLAN.md](PLAN.md) for the full architecture and phased roadmap.

## Status

Phase 1 (session-creation investigation), Phase 2 (the core service:
challenges, signature verification, identity mapping, linking, and the
HTTP endpoints), and Phase 5/6/7's UI (the standalone `/nostr-login` and
`/nostr-account` pages, NIP-07) are implemented and tested. Identity mapping
supports multiple linked devices per YunoHost account, with per-identity
labels, signer types, and revocation. See
[`PHASE0_INVESTIGATION.md`](PHASE0_INVESTIGATION.md) for the session-format
findings this is built against.

Short version of the one architectural wrinkle: there is no password-less
login function YunoHost exposes, and minting a `yunohost.portal` session
requires the privileges of the `ynh-portal` system user. Verified live
against a real (possibly containerized) YunoHost 12 install: a
`sudo`-spawned-per-request helper doesn't work there at all (something
sets the kernel's `no_new_privs` bit, which permanently blocks any
privilege escalation via `sudo`/setuid). Session minting instead runs as
its own always-running `ynh-portal`-owned systemd service
(`ynh/mint_session_server.py`), talked to over a Unix socket authenticated
by `SO_PEERCRED` - a privilege *drop* by systemd-as-root at service start,
not a *gain* by the daemon itself, so it isn't affected by that
restriction.

**The full login and linking flow is now verified end-to-end on a real
install**: real password login → our `/link/challenge` → sign → `/link` →
`200`, then `/challenge` → sign → `/authenticate` → `200` with a real,
decoded-and-checked `Set-Cookie: yunohost.portal=...` whose `email`/
`fullname` came from a genuine anonymous LDAP lookup. See
[`PHASE0_INVESTIGATION.md`](PHASE0_INVESTIGATION.md) for the full trail of
what broke and got fixed along the way (there were four real bugs, not
zero) and what's still open.

Phase 10 (NIP-46 remote signing - `bunker://` paste and a `nostrconnect://`
QR flow) is also implemented, on both pages, backed by a vendored
`nostr-tools` bundle (see `vendor/nostr-connect/`). Verified with a real,
unfaked NIP-46 handshake against a throwaway local relay and a small
"fake remote signer" script (both using `nostr-tools`' own primitives,
neither shipped): a genuinely `verifyEvent()`-valid signed event round-
tripped through the actual `BunkerSigner` client for both the `bunker://`
and `nostrconnect://` flows, and separately, both production pages'
own button-wiring was confirmed to correctly reach `/authenticate`/`/link`
using a mocked signer. The one thing *not* verified end-to-end is
`connectViaQr`'s hardcoded default relays (`relay.nsec.app`,
`relay.damus.io`) actually round-tripping a real signer connection - this
session's sandbox can't make outbound WebSocket connections to the public
internet from Node (confirmed: real relays work fine from the *browser*,
just not from the Node-based test signer), so that specific combination
wants a live check before relying on it.

The `/nostr-account` page also covers the rest of the user-profile surface
PLAN.md's Phase 5 left open: a "Saved on this device" panel lists whichever
of the NIP-46 bunker session / locally-generated key is currently saved in
this browser, each independently "Forget"-able without a full unlink;
unlinking now also clears both of those (previously a stale saved signer
could survive a server-side unlink); and a "Generate a new key pair" flow
lets someone without a Nostr identity yet create one entirely client-side
(never sent anywhere), with the raw key persisted in `localStorage` only if
they explicitly opt in via checkbox - unconditionally persisting it would
be the same risk class as storing a password there. `/nostr-login` gained
a matching "Sign in with saved key" button for that opt-in case. The passkey
flow can create a new identity or import the generated key into a WebAuthn
PRF-encrypted local vault; the decrypted key exists only in memory while
signing, and can be forgotten from the device independently of the
server-side link. The account page can also export the unlocked passkey
identity as an offline recovery nsec, with a warning that it grants full
signing control, and restore that nsec into a new passkey on another device.
Separately,
`GET /.well-known/nostr.json?name=<username>` exposes a linked identity as
a standard NIP-05 identifier (`<username>@<domain>`) for use by any Nostr
client or other app - not just other apps on the same YunoHost server -
without touching LDAP (PLAN.md Phase 4 deliberately deferred that);
strictly opt-in-by-linking and exact-name-only, never lists all linked
users. All of the above verified in a real browser against a locally run
instance of the service (mocked YunoHost portal auth, real crypto): keypair
generation → reveal/copy/remember → link → genuine signature verified
server-side; unlink → both `localStorage` keys confirmed cleared; saved-key
sign-in → real challenge signed and posted to `/authenticate`, correctly
accepted once linked and rejected while unlinked; NIP-05 endpoint resolves
the linked pubkey.

Phase 13's "minimum controls" checklist is now fully covered. Two real
gaps were found and fixed while going through it: `script-src` in
`CONTENT_SECURITY_POLICY` carried `'unsafe-inline'` (both pages' logic has
been moved out of an inline `<script>` into external
`web/static/nostr-*-page.js` files specifically so it no longer needs to -
`style-src` keeps it, since inline `<style>`/`style="..."` remain and CSS
injection isn't in the same severity class as script injection for this
threat model); and every audit-log line (`login success`, `identity
linked`, etc.) was silently dropped in production, since nothing ever
configured logging and Python's handler-of-last-resort only emits
WARNING+ - `server.py`'s `main()` now calls `logging.basicConfig(level=
logging.INFO)`. Rate limiting/brute-force throttling is handled the same
way YunoHost's own portal does it (`conf/fail2ban/yunohost-portal.conf`,
see `PHASE0_INVESTIGATION.md`): failed login/link/unlink attempts are
logged with the real client IP (`server.py`'s `_client_ip`, trusting
`X-Real-IP` - only valid because this service is only ever reached
through nostr_auth_ynh's own nginx, never directly) to a dedicated file a
`nostr_auth_ynh` fail2ban jail watches, rather than reimplementing IP
banning here. See that repo for the jail/systemd wiring.

`admin_cli.py` adds a second, admin-authority linking path alongside the
self-service one: `yunohost-nostr-auth-admin link/unlink/rename/revoke/list`, reached via
`nostr_auth_ynh`'s config-panel actions rather than a route on this
service - binds a pubkey to an account without requiring a live signature
from it, for provisioning an account for an agent/bot using an npub it
reports itself. See `docs/mcp-integration.md` for how this relates to
yunohost-mcp's separate pubkey→role/scope model.

The service also exposes independent `allow_nostr_login` and
`allow_identity_linking` policy switches. They pause the corresponding
self-service flows without deleting mappings; password login and admin
recovery remain available.

Challenge lifetime and clock-skew tolerance are bounded runtime settings as
well, allowing slow remote signers without permitting an accidentally huge
authentication window.

## Layout

```text
src/yunohost_nostr_auth/
    server.py              # the ASGI app: GET/POST routes wiring everything below together
    config.py              # NOSTR_AUTH_* environment settings
    admin_cli.py           # yunohost-nostr-auth-admin: admin-provisioned link/unlink/revoke/list,
                            # reached via nostr_auth_ynh's config-panel actions, not HTTP
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
        sessions.py             # unprivileged: talks to the socket below, holds no privilege itself
        mint_session_server.py  # privileged (own service, runs as ynh-portal): the socket listener
        portal_cookie.py        # privileged: reproduces YunoHost's JWT + session-file format
        ldap_lookup.py          # privileged: anonymous LDAP bind for cn/mail lookup
    web/
        page.py                # loads/caches the static pages/assets below, sets CSP
        nostr_login.html        # /nostr-login - sign in with an already-linked identity
                                 # (extension, NIP-46, or a saved locally-generated key)
        nostr_account.html      # /nostr-account - link/replace/unlink, generate a keypair,
                                 # and manage saved-signer state, for an already
                                 # password-authenticated session (PLAN.md Phase 5's UI)
        nostr_admin.html        # /nostr-admin - cross-user identity dashboard for YunoHost
                                 # admins (PLAN.md Phase 14), a modern alternative to the
                                 # generic YunoHost config-panel form
        static/
            nostr-connect-vendor.js  # vendored nostr-tools NIP-46 client (Phase 10) - see
                                      # vendor/nostr-connect/ for the build recipe
            nostr-passkey-vendor.js  # vendored nostr-passkey signer (Phase 11) - see
                                      # vendor/nostr-passkey/ for the build recipe
            nostr-connect-ui.js       # shared bunker://+QR+localStorage glue for both pages
            nostr-login-page.js       # /nostr-login's own logic - external, not inline, so
                                       # CONTENT_SECURITY_POLICY's script-src can be 'self' only
            nostr-account-page.js     # /nostr-account's own logic - same reason
            nostr-admin-page.js       # /nostr-admin's own logic - same reason

vendor/nostr-connect/    # the (not shipped) build recipe for nostr-connect-vendor.js
vendor/nostr-passkey/    # the (not shipped) build recipe for nostr-passkey-vendor.js
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

without modifying SSOwat or replacing core YunoHost files. Every step up
through "arrive at normal YunoHost portal" is now built and verified (the
`/nostr-login` page's JS wiring in a real browser with a simulated NIP-07
extension; the actual challenge/sign/authenticate/session-mint chain
against a real YunoHost 12 install - see the Status section above). What's
untested is the very last step: an actual NIP-07 extension in a real
browser, end to end, against a real linked account.
