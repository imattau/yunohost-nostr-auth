# YunoHost Nostr Authentication Add-on Plan

### Goal

Build a standalone YunoHost package, tentatively:

`nostr_auth_ynh`

with an underlying service:

`yunohost-nostr-auth`

The add-on should let an existing YunoHost user authenticate using a linked Nostr identity, initially via NIP-07, without replacing password login or requiring upstream YunoHost changes.

## Phase 1: Architecture and proof of concept

**Status: complete.** The session-creation investigation this phase calls for is
documented in `PHASE0_INVESTIGATION.md` (cookie format, signing mechanism, LDAP
relationship, and the four real bugs found getting a genuine session minted), and
the full loop below is verified end-to-end against a real YunoHost 12 install -
see README.md's Status section.

Start with the smallest possible working loop:

```text
Existing YunoHost user
        ↓
Link Nostr pubkey
        ↓
Visit separate Nostr login endpoint
        ↓
Receive one-time challenge
        ↓
Sign using NIP-07
        ↓
Server verifies signature
        ↓
pubkey → YunoHost username
        ↓
Create valid YunoHost session
        ↓
Redirect to YunoHost portal
```

The critical technical question is session creation. Before building anything substantial, inspect the current YunoHost 12 portal API and SSOwat implementation and document:

- exact session cookie format
- signing mechanism and secret location
- server-side session state
- expiry and refresh behaviour
- logout behaviour
- CSRF protections
- relationship between portal API, LDAP and SSOwat
- whether there is an internal callable login/session function that can be reused rather than replicated

Prefer invoking YunoHost's own session-creation code. Replicating session internals should be the fallback.

## Phase 2: Core `yunohost-nostr-auth` service

**Status: complete.** All six endpoints below are implemented in `server.py`
(a Starlette ASGI app) with the exact module layout this phase asks for, running
on localhost only behind nostr_auth_ynh's nginx. The service runs as its own
restricted system user with no general root access - see `ynh/permissions.py`
and PHASE0_INVESTIGATION.md's "privilege-drop redesign" for how session-minting
privilege is scoped down to just that.

Build a small local daemon, preferably Python or Go.

Suggested endpoints:

```text
GET  /challenge
POST /authenticate
POST /link/challenge
POST /link
POST /unlink
GET  /identity
```

The service should run only on localhost initially, with Nginx providing the external route.

Core modules:

```text
auth/
    challenge
    nostr_verify
    session

identity/
    mappings
    linking

ynh/
    users
    sessions
    permissions
```

Do not give the Nostr service general root access. Give it only the permissions required for YunoHost user lookup and session establishment.

## Phase 3: Challenge authentication

**Status: complete.** Every check below is implemented and tested:
`auth/challenge.py` issues CSPRNG (`secrets.token_urlsafe`), single-use,
expiring (default 90s, within the 30-120s window Phase 13 asks for) challenges
bound to a domain and action; `auth/nostr_verify.py` verifies the Schnorr
signature and NIP-01 structure via `nostr-sdk`, then checks the challenge/
domain/action tags and a created_at window against replay. Challenges are
consumed atomically by nonce before the signed event is ever checked.

Use a cryptographically random, short-lived, single-use challenge.

Authentication data should bind at least:

```text
nonce
domain
requested action
issued time
expiry
```

For example:

```text
action: yunohost-login
domain: example.org
nonce: ...
expires: ...
```

The signed object should also make replay against another YunoHost server impossible.

Checks must include:

- valid secp256k1/Schnorr signature
- valid Nostr event structure
- challenge exists
- challenge has not expired
- challenge has not already been consumed
- expected domain/origin matches
- expected authentication action matches
- timestamp within acceptable bounds

Consume the challenge atomically after successful authentication.

## Phase 4: Identity mapping

**Status: complete.** `identity/mappings.py` is a SQLite-backed store with
exactly the schema below (`ynh_username`, `pubkey`, `created_at`, `last_used`,
`enabled`), one pubkey per user. LDAP is untouched - see Phase 15/16 for where
that might eventually change. `npub` is decoded/encoded only at the UI
boundary (`identity/npub.py`); everywhere else, including the DB, stores the
canonical hex pubkey.

Initially avoid modifying the YunoHost LDAP schema.

Maintain an independent mapping database:

```text
YunoHost username
        ↕
Nostr pubkey
```

SQLite would be adequate.

Example schema:

```text
users
-----
ynh_username
pubkey
created_at
last_used
enabled
```

Support one pubkey per user initially.

Design the schema so multiple keys could be supported later.

Do not use `npub` internally. Decode it at the UI boundary and store the canonical hex public key.

## Phase 5: Secure account linking

**Status: complete.** Link/replace/unlink implemented and tested (`identity/linking.py`,
`/link/challenge`, `/link`, `/unlink`, `/identity`), with the `/nostr-account` UI covering
all three actions plus the rest of the profile surface this phase implies: viewing the
linked npub/NIP-05 identifier, a "Saved on this device" panel for managing a saved NIP-46
bunker session or locally-generated key independently of a full unlink, and a client-side
"generate a new key pair" flow for linking without an existing Nostr identity. See
README.md's Status section for the verification detail (real signature checks against a
live YunoHost install, and a browser-verified unlink correctly clearing saved signer state).

Never let an arbitrary Nostr pubkey claim an existing account.

Initial linking should require an already authenticated YunoHost session:

```text
Password login
     ↓
Account settings
     ↓
Link Nostr identity
     ↓
NIP-07 signs linking challenge
     ↓
backend verifies:
    current YNH session
    +
    Nostr signature
     ↓
mapping created
```

This creates a cryptographic association between the YunoHost account and the pubkey.

Provide:

```text
Link identity
Replace identity
Unlink identity
```

Replacing or removing a key should require current YunoHost authentication.

## Phase 6: Separate login page

**Status: complete.** `/nostr-login` implements exactly this flow, including
the final `/yunohost/sso/` redirect on success, plus (beyond this phase's
original scope) NIP-46 and saved-locally-generated-key sign-in alongside
NIP-07 - see Phase 10 and README.md's Status section.

Avoid changing the stock YunoHost portal initially.

Expose something like:

```text
https://example.org/nostr-login
```

UI:

```text
Sign in with Nostr
```

After authentication:

```text
/nostr-login
    ↓
sign
    ↓
verify
    ↓
YunoHost session
    ↓
302 /yunohost/sso/
```

This proves the backend integration before touching portal assets.

## Phase 7: NIP-07 support

**Status: complete.** Both `/nostr-login` and `/nostr-account` use
`window.nostr.signEvent`, and every listed edge case is handled explicitly in
their JS: no extension installed, a rejected signature request, an expired
challenge (surfaced as a server error message), a malformed/network failure,
and a `<noscript>` fallback for JavaScript disabled. The private key is never
requested or touched by this codebase - only `getPublicKey`/`signEvent`.

Implement NIP-07 first because it gives the simplest browser workflow:

```javascript
window.nostr.getPublicKey()
window.nostr.signEvent(...)
```

Handle cleanly:

- no Nostr extension
- extension locked
- user rejects signature
- wrong linked key
- expired challenge
- malformed event
- JavaScript disabled

Do not request access to the user's private key.

## Phase 8: YunoHost package

**Status: complete.** `nostr_auth_ynh` has this exact layout (plus `doc/`,
`conf/f2b_*`-generating fail2ban wiring, and a `conf/cron` self-heal - see
Phase 9 and 13). Every responsibility below is handled: a dedicated restricted
system user, SQLite DB preserved across upgrade via `resources.data_dir`,
systemd + nginx configuration, SSOwat permissions, the `/nostr-login` URL,
and clean removal - install/upgrade/remove all repeatedly verified against a
real YunoHost 12 server this session. `scripts/backup`/`restore` are now also
live-verified (full install→backup→remove→restore cycle against a real
server) - two real bugs turned up and got fixed: `scripts/restore` sourced
`_common.sh` via a relative path that only resolves during install/upgrade/
remove, not restore (which runs from a different working directory), and
`ynh_restore` (unlike `ynh_config_add_nginx`/`ynh_config_add_systemd`) never
reloads anything on its own, so a restored nginx conf and systemd units sat
correctly on disk but weren't actually picked up until the corresponding
services were told to reload. `change_url` is provided but untested this
session - lower-risk (no bespoke logic beyond re-rendering nginx for a new
domain and restarting), but still unverified.

Build:

```text
nostr_auth_ynh/
    manifest.toml
    scripts/
        install
        remove
        upgrade
        backup
        restore
        change_url
    conf/
        nginx.conf
        systemd.service
    sources/
```

Package responsibilities:

- install backend
- create restricted service user
- initialise identity DB
- install systemd service
- configure Nginx
- configure required YunoHost permissions
- expose the Nostr login URL
- preserve mappings across upgrade
- support backup/restore
- cleanly remove all integration

Avoid modifying generated YunoHost files.

## Phase 9: Portal integration

**Status: complete.** A "Login with Nostr" link is injected into the portal
via `nostr_auth_install_portal_patch`/`nostr_auth_remove_portal_patch` (a
single, idempotent, re-runnable function per this phase's requirement),
applied on install/upgrade and self-healed every 30 minutes via `conf/cron` +
`reapply-portal-patch.sh` for the "YunoHost upgrade silently reverts it" case
that has no clean core hook. Password login remains fully available
alongside it.

Once the standalone route works reliably, add:

```text
Login with Nostr
```

to the YunoHost login experience.

Prefer a supported extension or injected frontend asset mechanism.

If no clean portal extension point exists, isolate any patching into a single package function so it can be re-applied during:

```text
install
upgrade
YunoHost upgrade
```

Do not fork the whole portal.

Password login remains available.

## Phase 10: NIP-46

**Status: complete.** `bunker://` paste and a `nostrconnect://` QR flow are
implemented on both pages, backed by a vendored `nostr-tools` bundle (see
`vendor/nostr-connect/`), with connection metadata saved in `localStorage`
(now independently manageable/forgettable - Phase 5) and a signer timeout.
Verified with a real, unfaked NIP-46 handshake against a throwaway local
relay and a "fake remote signer" script - see README.md's Status section for
the one narrow thing that verification couldn't cover (the hardcoded default
relays' reachability from this sandbox specifically, not from a real
browser).

After NIP-07 is stable, add remote signing.

The browser becomes a NIP-46 client:

```text
YunoHost
   ↓
NIP-46 request
   ↓
remote signer / phone / bunker
   ↓
user approval
   ↓
signed authentication event
```

Important considerations:

- relay configuration
- connection URI handling
- signer timeout
- stale requests
- signer disconnect
- replay protection
- QR-code/mobile workflow
- local storage of connection metadata

NIP-07 and NIP-46 should ultimately feed the same verification pipeline.

## Phase 11: Passkeys

Do not initially make WebAuthn another YunoHost authentication implementation.

Instead support passkey-protected Nostr signers:

```text
Passkey / biometric
        ↓
unlock signer
        ↓
Nostr signature
        ↓
YunoHost
```

Later, direct WebAuthn authentication could be added as another provider if the architecture becomes generic.

## Phase 12: Recovery model

This needs explicit design.

Nostr login should initially be a convenience/security enhancement, not the only recovery path.

Default:

```text
YNH password authentication
+
Nostr authentication
```

If the user loses their Nostr key, they can:

```text
password login
→ unlink old key
→ link new key
```

Admins should also have a CLI recovery mechanism:

```bash
yunohost nostr-auth list
yunohost nostr-auth unlink matt
```

Do not create an irreversible Nostr-only mode in the first versions.

## Phase 13: Security controls

**Status: complete.** Every item below is implemented; see README.md's
Status section for the two real gaps this pass found and fixed (a
`script-src 'unsafe-inline'` CSP hole, and audit-log lines that were
silently dropped because nothing configured Python logging) and how
rate limiting/brute-force throttling is wired (a fail2ban jail in
`nostr_auth_ynh`, matching how YunoHost's own portal does it - see
`PHASE0_INVESTIGATION.md` - rather than reimplemented in-process).

Minimum controls:

- CSPRNG challenges
- single-use challenges
- 30 to 120 second expiry
- domain binding
- action binding
- signature verification server-side
- constant-time comparisons where appropriate
- rate limiting
- brute-force throttling
- audit logging
- no secret key storage
- secure HTTP-only session cookies
- TLS mandatory
- strict CSP on Nostr login page
- CSRF protection on account management
- no open redirect support

Audit log examples:

```text
nostr login success
nostr login failure
identity linked
identity replaced
identity removed
unknown pubkey attempted
replay rejected
```

Never log signed authentication payloads unnecessarily.

## Phase 14: Admin interface

Initially CLI:

```bash
yunohost nostr-auth status

yunohost nostr-auth users

yunohost nostr-auth show matt

yunohost nostr-auth unlink matt
```

Later integrate into the YunoHost admin UI.

Useful settings:

```text
Enable NIP-07
Enable NIP-46
Allow identity linking
Allow Nostr login
Session lifetime
Authentication event lifetime
```

Keep automatic account registration disabled by default.

## Phase 15: Optional Nostr account provisioning

Only after authentication is mature.

Possible policy:

```text
Disabled
Invite-only
Allowed pubkeys
Allowed NIP-05 domains
Open
```

A new pubkey could then create a YunoHost account.

However, provisioning and authentication should remain separate systems.

For example:

```text
Nostr proves identity
       ↓
policy determines eligibility
       ↓
YunoHost creates user
```

Never treat possession of a Nostr key alone as permission to create an account.

## Phase 16: Generic authentication provider layer

Once the Nostr implementation works, refactor internally:

```text
AuthenticationProvider
    challenge()
    authenticate()
    link()
    unlink()
    describe()
```

Providers might eventually include:

```text
password
nostr-nip07
nostr-nip46
webauthn
OIDC
```

At that point the project becomes more than a Nostr add-on. It becomes a prototype for pluggable YunoHost authentication.

## Suggested repository split

```text
github.com/imattau/yunohost-nostr-auth
```

Core service, protocol implementation and tests.

```text
github.com/imattau/nostr_auth_ynh
```

YunoHost packaging.

This matches the useful separation between application and YunoHost package.

## Development order

1. Reverse-engineer/document YunoHost 12 session creation.
2. Write Nostr challenge and verification library.
3. Build pubkey-to-YunoHost-user mapping.
4. Implement account linking.
5. Implement separate `/nostr-login` page.
6. Establish a real YunoHost session.
7. Verify SSOwat grants normal application access.
8. Package as `nostr_auth_ynh`.
9. Add backup/restore and upgrade handling.
10. Add portal login button.
11. Add NIP-46.
12. Add passkey-backed signer workflows.
13. Harden and threat-model.
14. Consider generic provider abstraction.
15. Only then consider upstreaming parts to YunoHost.

### First milestone

The first meaningful success criterion should be very narrow:

```text
Existing YunoHost user "matt"
has linked pubkey X

→ open /nostr-login
→ click Sign in with Nostr
→ approve NIP-07 signature
→ arrive at normal YunoHost portal
→ open an SSO-protected app
→ app recognises "matt"
```

If that works without modifying SSOwat or replacing core YunoHost files, the fundamental architecture is proven.

The most important implementation rule is to keep the Nostr layer responsible for **proving identity**, while YunoHost remains responsible for **users, groups, permissions and sessions**. That keeps the add-on small and limits the amount of YunoHost internals it needs to own.
