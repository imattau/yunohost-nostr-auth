# Phase 1 Investigation: YunoHost 12 portal session creation

Sources (shallow clones, `dev` branch, read at the commits below):

- `github.com/YunoHost/yunohost` @ `c206fff7` (tag `debian/12.1.41.2`, 2026-09-04) — satisfies `nostr_auth_ynh`'s manifest requirement `yunohost >= 12.1.17`.
- `github.com/YunoHost/moulinette` @ `0e8aa813` (tag `debian/12.1.4`) — the framework yunohost's portal API is built on.
- `github.com/YunoHost/SSOwat` @ `a59b558b` (tag `debian/12.1.1`) — the nginx/Lua module that actually gatekeeps app requests.

No live YunoHost 12 server was available to test this against directly; everything below is read from source. It should be spot-checked against a real install (file permissions in particular) before Phase 2 code is written against it.

## The pieces, and how they fit together

YunoHost 12 replaced the old all-Lua SSOwat portal with a split design:

- **`yunohost-portal-api`** (`bin/yunohost-portal-api`, `src/portal.py`) — a small bottle/moulinette API, run by systemd as an unprivileged `ynh-portal` system user, listening on `127.0.0.1:6788`. Nginx proxies `/yunohost/portalapi/` to it (`conf/nginx/yunohost_api.conf.inc`). This is what handles login, logout, and "my account" (`GET /me`, `PUT /update`, ...).
- **`/yunohost/sso/`** — a static Vue.js frontend (`alias /usr/share/yunohost/portal/`), served directly by nginx. It's what a browser actually loads; it talks to `yunohost-portal-api` over `/yunohost/portalapi/` from JS.
- **SSOwat** (`/etc/ssowat/access.lua`, loaded via nginx's `access_by_lua_file`) — runs on *every* request to a protected domain. It does **not** call back into `yunohost-portal-api` at request time. Instead it independently re-verifies the same JWT cookie using the same shared secret, and stat()s a session-touch-file. This means minting a valid session is entirely about producing the right cookie + touch-file; there is no network call SSOwat makes to check it.
- **`yunohost-api`** (port 6787, `/yunohost/api/`) — the separate *admin* API (webadmin), with its own cookie (`yunohost.admin`), its own secret (`/etc/yunohost/.admin_cookie_secret`), its own session folder (`/var/cache/yunohost/sessions`, root-only). Not relevant to this project — we only care about the regular-user portal, not admin sessions.

This confirms PLAN.md's separation is right: "proving identity" (Nostr) can stay entirely outside this, if we can produce what the portal API produces.

## Exact session cookie format

`src/authenticators/ldap_ynhuser.py` (`Authenticator` class) is the single source of truth. Cookie name: `yunohost.portal`.

```python
SESSION_SECRET_PATH = Path("/etc/yunohost/.ssowat_cookie_secret")
SESSION_FOLDER = Path("/var/cache/yunohost-portal/sessions")
SESSION_VALIDITY = 3 * 24 * 3600  # 3 days
```

`set_session_cookie(infos)` (ldap_ynhuser.py:255) does two things:

1. Adds `infos["id"] = short_hash(infos["user"]) + random_ascii(20)` (`short_hash` = `hashlib.shake_256(...).hexdigest(20)`) and `infos["host"] = request.get_header("host")`, then sets the cookie to `jwt.encode(infos, SESSION_SECRET(), algorithm="HS256")` — a plain HS256 JWT, not encrypted, just signed. Required claims (enforced on read via `options={"require": [...]}`): `id`, `host`, `user`, `pwd`. `email` and `fullname` are also always set by the real login path but aren't in the "required" list.
2. Touches an empty file at `SESSION_FOLDER / infos["id"]` — this file's **mtime is the actual expiry clock**, both server-side (`get_session_cookie` checks it, `purge_expired_session_files` deletes stale ones) and in SSOwat (`access.lua` checks `os.time() - mtime > 3*24*3600`). The JWT itself carries no `exp` claim — the cookie's own `max_age` (browser-enforced only) is set to `SESSION_VALIDITY - 600`, but the file's mtime is what every server-side check actually relies on.

Cookie attributes: `secure=True, httponly=True, path="/", samesite="lax", domain=".{host}"` — `samesite` is `None` only if `/etc/yunohost/.portal-api-allowed-cors-origins` exists (an explicit dev-mode marker file), which also affects nothing else here. **`domain=".{host}"` matters**: cookies are scoped to the exact `Host` header of the request, with a leading dot — so a session minted for `example.org` will also be sent for `sub.example.org`, and `get_session_cookie` explicitly checks `infos["host"] != request.get_header("host")` (not a suffix check) before falling through — the suffix behavior is standard cookie domain-matching, not something the app code re-implements). This is the "domain binding" PLAN.md Phase 3 asks for at the Nostr-challenge level too; it already exists at the session level for free.

The **`pwd`** field is the interesting one: `encrypt(password)` — AES-256-CBC, keyed by the *same* 32-byte secret used for the JWT's HMAC key, formatted as `<b64 ciphertext>|<b64 iv>`. It exists so that:
- `portal_update()` (`src/portal.py:294-321`) can re-open an authenticated LDAP connection as the user (`LDAPInterface(username, Auth().get_session_cookie(decrypt_pwd=True)["pwd"])`) when the caller doesn't supply `currentpassword` explicitly — used for any profile edit, not just password changes.
- SSOwat's `access.lua` (lines 292-320) decrypts it too, to inject a `Basic <user>:<password>` `Authorization` header into the proxied request, for legacy apps that authenticate via HTTP Basic Auth rather than reading YNH_USER headers (permission's basic-auth injection setting).

**Consequence for Nostr login: we do not have — and should never obtain — the user's LDAP password.** A session minted by our service literally cannot populate a real `pwd`. Both consumers of that field will then either fail (profile edits without `currentpassword` — will 401/error from LDAP) or misbehave (legacy Basic-Auth apps will see a bogus password and likely reject the user). This is a real, permanent limitation of Nostr-only sessions, not a bug to fix — see Conclusions.

## Secrets, session storage, and exactly who can touch them

`hooks/conf_regen/01-yunohost` (lines 46-90) is what creates and chmods everything, and — importantly — **re-applies these permissions every time `yunohost tools regen-conf` runs**, so anything we do must survive that, not just survive install:

```
useradd --no-create-home --shell /usr/sbin/nologin --system --user-group ynh-portal

chown ynh-portal:ynh-portal /etc/yunohost/portal
chown ynh-portal:root       /var/log/yunohost-portalapi.log

mkdir -p /var/cache/yunohost-portal/sessions
chown ynh-portal:www-data /var/cache/yunohost-portal
chown ynh-portal:www-data /var/cache/yunohost-portal/sessions
chmod 710                 /var/cache/yunohost-portal/sessions

# .ssowat_cookie_secret: 32 random alphanumeric chars
chown ynh-portal:root /etc/yunohost/.ssowat_cookie_secret
chmod 400             /etc/yunohost/.ssowat_cookie_secret
```

- The secret is `-rw------- ynh-portal:root`, mode `400`. Group is `root`, but the group permission bits are `0` — group membership grants nothing here. **Only the literal `ynh-portal` user (or actual root, which bypasses permission bits entirely) can read this file.** There is no group we can join to get read access without either running as `ynh-portal`, running as root, or the YunoHost project adding an ACL/group for this on our behalf (an upstream change, which PLAN.md rules out for now).
- The session folder is `drwx--x--- ynh-portal:www-data` (`710`): owner (`ynh-portal`) has full rwx; group (`www-data`, the nginx user) has **execute only** — enough for SSOwat's `lfs.attributes()` to `stat()` a session file it already knows the name of, but not enough to list the directory or, critically, **not enough to create a new session file**. Only `ynh-portal` (or root) can write a new session there.

So: **the only ways to produce a valid `yunohost.portal` cookie are (a) knowing the user's LDAP password and calling the real login endpoint, or (b) running with the actual privileges of the `ynh-portal` system user (or root).** There is no narrower privilege that works, and no supported extension point that lets an external service ask `yunohost-portal-api` to mint a session for a user it hasn't password-authenticated. This directly answers PLAN.md's open question: no, there is currently no internal callable "log this user in, no password needed" function exposed anywhere in the stack — `Authenticator.set_session_cookie()` is that function, but it's private to the `yunohost-portal-api` process's own privilege level, not something another process can invoke remotely or in-process without becoming (or impersonating) `ynh-portal`.

## The real login/logout HTTP surface (for reference / comparison)

Wired by `moulinette/interfaces/api.py`'s `ApiActionsMapPlugin.setup()` (lines 333-348), reused as-is by the portal API (`share/actionsmap-portal.yml` only declares `_global.authentication.api: ldap_ynhuser`, no custom login route):

- `POST /yunohost/portalapi/login` — body either `{"credentials": "user:pass"}` (JSON) or form fields `username`/`password`. Calls `Authenticator.authenticate_credentials()` → LDAP `simple_bind_s` as the user (`src/authenticators/ldap_ynhuser.py:190-253`, also re-checks `user_is_allowed_on_domain` for the requesting `Host`) → on success, `set_session_cookie(auth_infos)`. On failure: `401`. `conf/fail2ban/yunohost-portal.conf` watches exactly this path/status for brute-force banning.
- `GET /yunohost/portalapi/logout` — `delete_session_cookie()`: unlinks the session file, clears the cookie. No CSRF concern (GET-only).
- CSRF (`moulinette/interfaces/api.py:56-81`): a `POST` is treated as CSRF **only** if its `Content-Type` is `text/plain`, `application/x-www-form-urlencoded`, or `multipart/form-data` **and** it has no `X-Requested-With` header. A JSON-bodied POST (`application/json`) is never flagged. This is the existing convention our own `/authenticate`, `/link`, `/unlink` endpoints (PLAN.md Phase 2/13) should follow: require JSON bodies (or an `X-Requested-With` header), don't accept bare form-encoded POSTs.
- Logging out or changing password calls `Authenticator.invalidate_all_sessions_for_user(username)` (ldap_ynhuser.py:366), which deletes every session file whose name starts with `short_hash(username)` — indiscriminate of how the session was created. A Nostr-established session is invalidated the same way a password change would invalidate it; no special-casing needed for that.

## Conclusions — answering PLAN.md's Phase 1 checklist

| Question | Answer |
|---|---|
| Session cookie format | HS256 JWT (`yunohost.portal`), claims `id, host, user, pwd, email, fullname`; not encrypted, just signed. `id` doubles as the session-file name. |
| Signing mechanism / secret location | HMAC-SHA256 over the JWT, same 32-char secret also used as an AES-256-CBC key for the `pwd` field. Secret at `/etc/yunohost/.ssowat_cookie_secret`, mode `400` owned `ynh-portal:root` — readable only by `ynh-portal` or root. |
| Server-side session state | A touch-file per session at `/var/cache/yunohost-portal/sessions/<id>` (dir mode `710`, owned `ynh-portal:www-data`). Its **mtime**, not any JWT claim, is the actual expiry clock everywhere (portal API and SSOwat both). Writable only by `ynh-portal`/root. |
| Expiry & refresh | 3 days, refreshed (mtime touched, cookie re-set) on every authenticated portal-API request via `get_session_cookie()`. SSOwat does not refresh it — only the portal API does. |
| Logout | `GET /yunohost/portalapi/logout` → delete cookie + unlink session file. |
| CSRF protections | JSON-bodied (or `X-Requested-With`-carrying) requests are exempt from moulinette's CSRF filter; plain form POSTs without that header are rejected with 403. |
| Portal API ↔ LDAP ↔ SSOwat relationship | Portal API authenticates against LDAP directly (`simple_bind_s`) and is the only writer of sessions. SSOwat (nginx/Lua, runs on every request) independently re-verifies the same JWT + session file — it never calls the portal API. Both trust the same shared secret file. |
| Internal callable login function to reuse? | **No, not one we can call from outside `ynh-portal`'s privilege boundary.** `Authenticator.set_session_cookie()` is exactly that function, but it requires (a) LDAP-verified credentials as input and (b) filesystem privilege only `ynh-portal`/root has, to read the secret and write the session file. There's no lower-privilege or password-less path anywhere in this stack, by design — YunoHost has no concept of "log this user in without a password" at all yet. |

**This settles the architecture for Phase 2 onward:** our `ynh/sessions.py` cannot get away with staying unprivileged. The `yunohost-nostr-auth` service itself should stay unprivileged (no root, no `ynh-portal` membership) and be responsible only for challenge issuance/verification and the pubkey↔username mapping, per PLAN.md's "least privilege" instruction. Session *minting* has to happen via a narrowly-scoped, separately-invoked privileged helper that:

1. Runs as `ynh-portal` (not root) — e.g. `sudo -u ynh-portal` restricted by a sudoers rule to exactly one fixed helper script/binary with no attacker-controlled arguments beyond a already-verified `ynh_username`; the main daemon never runs as `ynh-portal` itself.
2. Reproduces exactly the cookie/session-file shape documented above (JWT claims, HS256, session-file touch) rather than reinventing it — this is "replicate the fallback" per PLAN.md, but scoped to one small, heavily-commented function that cites `ldap_ynhuser.py` by path and commit, and that gets re-diffed against upstream on every YunoHost core version bump (a packaging-time or CI check, not just a one-time read).
3. Sets `pwd` to an encrypted **empty string**, not a real password, and documents (doc/ADMIN.md) that Nostr-authenticated sessions cannot edit profile fields or use Basic-Auth-only legacy apps without re-authenticating with a password first — this is a real, permanent limitation of a passwordless login method against this particular session design, not a Phase-2 bug.
4. Is re-verified against the actual `/etc/yunohost/.ssowat_cookie_secret` permissions and `/var/cache/yunohost-portal/sessions` mode on a real YunoHost 12 install before Phase 2 ships (everything above is read from source, not empirically confirmed on a live box).

This maps onto the module layout already scaffolded:

- `auth/session.py` stays the "ask for a session" entry point the HTTP handlers call; it now calls out to...
- `ynh/sessions.py` — the actual privileged-helper invocation (Phase 2 will add the sudoers rule + helper script here, packaged by `nostr_auth_ynh`'s `scripts/install`).
- `ynh/permissions.py` — documents/enforces exactly this boundary: what the unprivileged daemon can do vs. what only the `ynh-portal`-privileged helper can do.

## Open items before Phase 2 code is finalized

- Confirm on a real YunoHost 12.1.x box that `/etc/yunohost/.ssowat_cookie_secret` and `/var/cache/yunohost-portal/sessions` permissions match what's read from source here.
- Decide the exact privilege-drop mechanism for the helper (`sudo -u ynh-portal`, a systemd `User=ynh-portal` oneshot unit triggered via a socket, or something else) — a job for early Phase 2, not this doc.
- Track `ldap_ynhuser.py` upstream for changes across YunoHost releases; this whole document is a snapshot of one commit.
