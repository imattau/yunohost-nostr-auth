# YunoHost Nostr Authentication Add-on Plan

### Goal

Build a standalone YunoHost package, tentatively:

`nostr_auth_ynh`

with an underlying service:

`yunohost-nostr-auth`

The add-on should let an existing YunoHost user authenticate using a linked Nostr identity, initially via NIP-07, without replacing password login or requiring upstream YunoHost changes.

## Phase 1: Architecture and proof of concept

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
