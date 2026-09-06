"""ASGI app wiring together the endpoints described in PLAN.md's Phase 2:

    GET  /challenge
    POST /authenticate
    POST /link/challenge
    POST /link
    POST /unlink
    GET  /identity

...plus the standalone pages from Phase 5/6/7:

    GET  /nostr-login    - sign in with an already-linked identity
    GET  /nostr-account  - link/replace/unlink, for an already
                            password-authenticated YunoHost session
    GET  /nostr-admin    - cross-user identity dashboard, gated on the
                            "admins" YunoHost group (see /nostr-admin/api/*)
    GET  /static/nostr-connect-vendor.js  - vendored nostr-tools NIP-46 client (Phase 10)
    GET  /static/nostr-connect-ui.js      - shared NIP-46 UI glue for the two pages above

...plus NIP-05, for exposing a linked identity outside YunoHost entirely:

    GET  /.well-known/nostr.json

Runs on localhost only; Nginx (see the nostr_auth_ynh package) provides the
external route and TLS termination.

Following the CSRF convention PHASE0_INVESTIGATION.md found the real
YunoHost portal API uses: every POST here must be JSON-bodied
(`Content-Type: application/json`) - moulinette's own CSRF filter exempts
JSON POSTs (on the theory that a cross-origin form/fetch can't set that
content type without a CORS preflight), and there's no reason for our
POSTs to accept form-encoded bodies at all.
"""

from __future__ import annotations

import json
import logging

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from yunohost_nostr_auth.auth import login, nostr_verify
from yunohost_nostr_auth.auth.challenge import ChallengeStore
from yunohost_nostr_auth.config import Settings, get_settings
from yunohost_nostr_auth.identity import linking, npub
from yunohost_nostr_auth.identity.mappings import MappingStore, PubkeyAlreadyLinked
from yunohost_nostr_auth.web.page import (
    CONTENT_SECURITY_POLICY,
    content_type_for_static_asset,
    read_static_asset,
    render_account_page,
    render_admin_page,
    render_login_page,
)
from yunohost_nostr_auth.ynh import portal_client
from yunohost_nostr_auth.ynh.sessions import SessionMintError

logger = logging.getLogger("yunohost_nostr_auth.server")

LOGIN_ACTION = login.LOGIN_ACTION
LINK_ACTION = linking.LINK_ACTION
ALLOWED_ACTIONS = {LOGIN_ACTION, LINK_ACTION}


def _client_ip(request: Request) -> str:
    """The real client IP, not the nginx proxy's.

    nostr_auth_ynh's nginx config always sets X-Real-IP from $remote_addr
    (see proxy_params_no_auth, YunoHost's own baseline) - unlike
    Authorization or other app-facing headers, nginx's proxy_set_header
    unconditionally *overwrites* rather than forwards this, so a client
    can't spoof it by sending its own X-Real-IP. Only trust it because
    this service listens on 127.0.0.1 and is only ever reached through
    that nginx, never directly from the internet.
    """
    return request.headers.get("x-real-ip") or (
        request.client.host if request.client else "unknown"
    )


def _require_json(request: Request) -> None:
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise _ApiError(415, "Content-Type must be application/json")


class _ApiError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


async def challenge_endpoint(request: Request) -> Response:
    action = request.query_params.get("action", LOGIN_ACTION)
    if action not in ALLOWED_ACTIONS:
        raise _ApiError(400, f"unknown action {action!r}")
    if action == LOGIN_ACTION and not get_settings().allow_nostr_login:
        raise _ApiError(403, "Nostr login is currently disabled")

    domain = request.headers.get("host")
    if not domain:
        raise _ApiError(400, "missing Host header")

    store: ChallengeStore = request.app.state.challenge_store
    challenge = store.issue(domain=domain, action=action)

    return JSONResponse(
        {
            "kind": nostr_verify.CHALLENGE_EVENT_KIND,
            "nonce": challenge.nonce,
            "domain": challenge.domain,
            "action": challenge.action,
            "issued_at": challenge.issued_at,
            "expires_at": challenge.expires_at,
        }
    )


async def authenticate_endpoint(request: Request) -> Response:
    _require_json(request)
    settings = get_settings()
    if not settings.allow_nostr_login:
        raise _ApiError(403, "Nostr login is currently disabled")
    body = await request.json()
    event = body.get("event")
    if not isinstance(event, dict):
        raise _ApiError(400, "missing 'event'")

    nonce = nostr_verify.extract_tag_from_raw_event(event, "challenge")
    challenge_store: ChallengeStore = request.app.state.challenge_store
    challenge = challenge_store.consume(nonce) if nonce else None

    mappings: MappingStore = request.app.state.mappings
    try:
        minted = login.authenticate(
            mappings,
            challenge=challenge,
            event_json=json.dumps(event),
            clock_skew=settings.clock_skew_seconds,
        )
    except login.LoginError as e:
        # PLAN.md Phase 13: rate limiting / brute-force throttling. This
        # exact "... failure from <ip>: ..." shape is what
        # nostr_auth_ynh's fail2ban filter matches - see server.py's
        # _client_ip and conf/f2b_filter.conf in that repo.
        logger.warning("nostr login failure from %s: %s", _client_ip(request), e)
        raise _ApiError(401, str(e)) from e
    except SessionMintError as e:
        logger.error("nostr login: session minting failed: %s", e)
        raise _ApiError(502, "could not establish a YunoHost session") from e

    logger.info("nostr login success from %s", _client_ip(request))
    response = JSONResponse({"ok": True})
    response.set_cookie(
        minted.cookie_name,
        minted.token,
        max_age=minted.max_age,
        path="/",
        domain=f".{request.headers.get('host')}",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return response


async def link_challenge_endpoint(request: Request) -> Response:
    if not get_settings().allow_identity_linking:
        raise _ApiError(403, "self-service identity linking is currently disabled")
    domain = request.headers.get("host")
    if not domain:
        raise _ApiError(400, "missing Host header")

    store: ChallengeStore = request.app.state.challenge_store
    challenge = store.issue(domain=domain, action=LINK_ACTION)

    return JSONResponse(
        {
            "kind": nostr_verify.CHALLENGE_EVENT_KIND,
            "nonce": challenge.nonce,
            "domain": challenge.domain,
            "action": challenge.action,
            "issued_at": challenge.issued_at,
            "expires_at": challenge.expires_at,
        }
    )


async def link_endpoint(request: Request) -> Response:
    _require_json(request)
    if not get_settings().allow_identity_linking:
        raise _ApiError(403, "self-service identity linking is currently disabled")
    body = await request.json()
    event = body.get("event")
    if not isinstance(event, dict):
        raise _ApiError(400, "missing 'event'")
    signer_type, label = _identity_metadata(body)

    cookie_header = request.headers.get("cookie")
    if not cookie_header:
        raise _ApiError(401, "not currently logged in to YunoHost")

    nonce = nostr_verify.extract_tag_from_raw_event(event, "challenge")
    challenge_store: ChallengeStore = request.app.state.challenge_store
    challenge = challenge_store.consume(nonce) if nonce else None

    settings = get_settings()
    mappings: MappingStore = request.app.state.mappings
    try:
        username = linking.confirm_and_link(
            mappings,
            cookie_header=cookie_header,
            host=request.headers.get("host", ""),
            challenge=challenge,
            event_json=json.dumps(event),
            signer_type=signer_type,
            label=label,
            clock_skew=settings.clock_skew_seconds,
            portal_api_base_url=settings.portal_api_base_url,
        )
    except linking.LinkingError as e:
        logger.warning("identity link failure from %s: %s", _client_ip(request), e)
        raise _ApiError(401, str(e)) from e

    logger.info("identity linked (%s) from %s", username, _client_ip(request))
    return JSONResponse({"ok": True, "username": username})


async def unlink_endpoint(request: Request) -> Response:
    cookie_header = request.headers.get("cookie")
    if not cookie_header:
        raise _ApiError(401, "not currently logged in to YunoHost")

    settings = get_settings()
    mappings: MappingStore = request.app.state.mappings
    try:
        username = linking.confirm_and_unlink(
            mappings,
            cookie_header=cookie_header,
            host=request.headers.get("host", ""),
            portal_api_base_url=settings.portal_api_base_url,
        )
    except linking.LinkingError as e:
        logger.warning("identity unlink failure from %s: %s", _client_ip(request), e)
        raise _ApiError(401, str(e)) from e

    logger.info("identity removed (%s) from %s", username, _client_ip(request))
    return JSONResponse({"ok": True, "username": username})


async def identity_endpoint(request: Request) -> Response:
    cookie_header = request.headers.get("cookie")
    if not cookie_header:
        raise _ApiError(401, "not currently logged in to YunoHost")

    settings = get_settings()
    try:
        username = portal_client.get_authenticated_username(
            cookie_header, host=request.headers.get("host", ""), base_url=settings.portal_api_base_url
        )
    except portal_client.PortalAuthError as e:
        raise _ApiError(401, str(e)) from e

    mappings: MappingStore = request.app.state.mappings
    identity = mappings.get_by_username(username)
    if identity is None or not identity.enabled:
        return JSONResponse({"linked": False})

    return JSONResponse(
        {
            "linked": True,
            "username": username,
            "pubkey": identity.pubkey,
            "npub": npub.hex_to_npub(identity.pubkey),
            "created_at": identity.created_at,
            "last_used": identity.last_used,
        }
    )


def _identity_json(identity) -> dict:
    return {
        "id": identity.identity_id,
        "username": identity.ynh_username,
        "pubkey": identity.pubkey,
        "npub": npub.hex_to_npub(identity.pubkey),
        "created_at": identity.created_at,
        "last_used": identity.last_used,
        "enabled": identity.enabled,
        "signer_type": identity.signer_type,
        "label": identity.label,
        "linked_by": identity.linked_by,
        "revoked_at": identity.revoked_at,
    }


def _identity_metadata(body: dict) -> tuple[str, str | None]:
    signer_type = body.get("signer_type", "unknown")
    label = body.get("label")
    if not isinstance(signer_type, str) or signer_type not in {"unknown", "nip07", "nip46", "passkey"}:
        raise _ApiError(400, "invalid signer_type")
    if label is not None and (not isinstance(label, str) or not label.strip() or len(label) > 120):
        raise _ApiError(400, "label must be a non-empty string of at most 120 characters")
    return signer_type, label.strip() if isinstance(label, str) else None


def _authenticated_username(request: Request, settings: Settings) -> str:
    cookie_header = request.headers.get("cookie")
    if not cookie_header:
        raise _ApiError(401, "not currently logged in to YunoHost")
    try:
        return portal_client.get_authenticated_username(
            cookie_header, host=request.headers.get("host", ""), base_url=settings.portal_api_base_url
        )
    except portal_client.PortalAuthError as e:
        raise _ApiError(401, str(e)) from e


def _authenticated_admin(request: Request, settings: Settings) -> str:
    """Like :func:`_authenticated_username`, but also requires the "admins"
    YunoHost group - the same membership real yunohost-portal-api checks
    for its own admin-gated actions. Reaching /nostr-admin's API at all
    means this exact browser session already has full YunoHost admin
    authority, which is why its identity-management actions below don't
    need a second, separate confirmation the way a live-signature-backed
    self-service link does.
    """
    cookie_header = request.headers.get("cookie")
    if not cookie_header:
        raise _ApiError(401, "not currently logged in to YunoHost")
    try:
        session = portal_client.get_authenticated_session(
            cookie_header, host=request.headers.get("host", ""), base_url=settings.portal_api_base_url
        )
    except portal_client.PortalAuthError as e:
        raise _ApiError(401, str(e)) from e
    if not session.is_admin:
        raise _ApiError(403, "YunoHost admin access is required")
    return session.username


async def admin_session_endpoint(request: Request) -> Response:
    """Lets /nostr-admin's page distinguish "not logged in", "logged in but
    not an admin", and "logged in as an admin" without every check raising
    the same opaque 401/403 - separate from every other admin endpoint,
    which do require full admin access to even respond.
    """
    cookie_header = request.headers.get("cookie")
    if not cookie_header:
        return JSONResponse({"authenticated": False, "is_admin": False})

    settings = get_settings()
    try:
        session = portal_client.get_authenticated_session(
            cookie_header, host=request.headers.get("host", ""), base_url=settings.portal_api_base_url
        )
    except portal_client.PortalAuthError:
        return JSONResponse({"authenticated": False, "is_admin": False})

    return JSONResponse(
        {"authenticated": True, "is_admin": session.is_admin, "username": session.username}
    )


async def admin_list_identities_endpoint(request: Request) -> Response:
    settings = get_settings()
    _authenticated_admin(request, settings)
    identities = request.app.state.mappings.list_all()
    return JSONResponse({"identities": [_identity_json(identity) for identity in identities]})


def _admin_target(body: dict) -> str:
    username = body.get("username")
    if not isinstance(username, str) or not username.strip():
        raise _ApiError(400, "missing 'username'")
    return username.strip()


async def admin_add_identity_endpoint(request: Request) -> Response:
    _require_json(request)
    settings = get_settings()
    _authenticated_admin(request, settings)
    body = await request.json()

    username = _admin_target(body)
    pubkey_or_npub = body.get("pubkey")
    if not isinstance(pubkey_or_npub, str) or not pubkey_or_npub.strip():
        raise _ApiError(400, "missing 'pubkey' (npub or hex)")
    try:
        pubkey_hex = npub.parse_to_hex(pubkey_or_npub.strip())
    except ValueError as e:
        raise _ApiError(400, str(e)) from e
    signer_type, label = _identity_metadata(body)
    replace = bool(body.get("replace", False))

    mappings: MappingStore = request.app.state.mappings
    try:
        if replace:
            mappings.link(username, pubkey_hex, signer_type=signer_type, label=label, linked_by="admin")
            identity = mappings.get_by_pubkey(pubkey_hex)
        else:
            identity = mappings.add_identity(
                username, pubkey_hex, signer_type=signer_type, label=label, linked_by="admin"
            )
    except PubkeyAlreadyLinked as e:
        raise _ApiError(409, str(e)) from e

    logger.info("admin added identity (%s) from %s", username, _client_ip(request))
    return JSONResponse({"ok": True, "username": username, "identity": _identity_json(identity)})


async def admin_revoke_identity_endpoint(request: Request) -> Response:
    _require_json(request)
    settings = get_settings()
    _authenticated_admin(request, settings)
    body = await request.json()
    username = _admin_target(body)
    try:
        identity_id = int(request.path_params["identity_id"])
    except (TypeError, ValueError):
        raise _ApiError(400, "identity id must be an integer") from None

    if not request.app.state.mappings.revoke_identity(identity_id, username):
        raise _ApiError(404, "identity not found or already revoked")

    logger.info("admin revoked identity (%s, id=%s) from %s", username, identity_id, _client_ip(request))
    return JSONResponse({"ok": True, "username": username, "identity_id": identity_id})


async def admin_rename_identity_endpoint(request: Request) -> Response:
    _require_json(request)
    settings = get_settings()
    _authenticated_admin(request, settings)
    body = await request.json()
    username = _admin_target(body)
    label = body.get("label")
    if not isinstance(label, str) or not label.strip() or len(label) > 120:
        raise _ApiError(400, "label must be a non-empty string of at most 120 characters")
    try:
        identity_id = int(request.path_params["identity_id"])
    except (TypeError, ValueError):
        raise _ApiError(400, "identity id must be an integer") from None

    identity = request.app.state.mappings.update_identity_label(identity_id, username, label.strip())
    if identity is None:
        raise _ApiError(404, "identity not found or revoked")

    logger.info("admin renamed identity (%s, id=%s) from %s", username, identity_id, _client_ip(request))
    return JSONResponse({"ok": True, "username": username, "identity": _identity_json(identity)})


async def admin_unlink_endpoint(request: Request) -> Response:
    _require_json(request)
    settings = get_settings()
    _authenticated_admin(request, settings)
    body = await request.json()
    username = _admin_target(body)

    request.app.state.mappings.unlink(username)
    logger.info("admin unlinked all identities (%s) from %s", username, _client_ip(request))
    return JSONResponse({"ok": True, "username": username})


async def admin_page(request: Request) -> Response:
    return HTMLResponse(render_admin_page(), headers={"Content-Security-Policy": CONTENT_SECURITY_POLICY})


async def identities_endpoint(request: Request) -> Response:
    settings = get_settings()
    username = _authenticated_username(request, settings)
    identities = request.app.state.mappings.list_by_username(username)
    return JSONResponse(
        {"username": username, "identities": [_identity_json(identity) for identity in identities]}
    )


async def policy_endpoint(request: Request) -> Response:
    """Expose only the public policy switches needed by the web pages."""
    settings = get_settings()
    return JSONResponse(
        {
            "allow_nostr_login": settings.allow_nostr_login,
            "allow_identity_linking": settings.allow_identity_linking,
        }
    )


async def add_identity_endpoint(request: Request) -> Response:
    _require_json(request)
    if not get_settings().allow_identity_linking:
        raise _ApiError(403, "self-service identity linking is currently disabled")
    body = await request.json()
    event = body.get("event")
    if not isinstance(event, dict):
        raise _ApiError(400, "missing 'event'")

    signer_type, label = _identity_metadata(body)

    cookie_header = request.headers.get("cookie")
    if not cookie_header:
        raise _ApiError(401, "not currently logged in to YunoHost")

    nonce = nostr_verify.extract_tag_from_raw_event(event, "challenge")
    challenge = request.app.state.challenge_store.consume(nonce) if nonce else None

    settings = get_settings()
    try:
        username = linking.confirm_and_add(
            request.app.state.mappings,
            cookie_header=cookie_header,
            host=request.headers.get("host", ""),
            challenge=challenge,
            event_json=json.dumps(event),
            signer_type=signer_type,
            label=label,
            clock_skew=settings.clock_skew_seconds,
            portal_api_base_url=settings.portal_api_base_url,
        )
    except linking.LinkingError as e:
        logger.warning("identity add failure from %s: %s", _client_ip(request), e)
        raise _ApiError(401, str(e)) from e

    logger.info("identity added (%s) from %s", username, _client_ip(request))
    identity = request.app.state.mappings.get_by_username(username)
    return JSONResponse({"ok": True, "username": username, "identity": _identity_json(identity)})


async def revoke_identity_endpoint(request: Request) -> Response:
    settings = get_settings()
    username = _authenticated_username(request, settings)
    raw_identity_id = request.path_params["identity_id"]
    try:
        identity_id = int(raw_identity_id)
    except (TypeError, ValueError):
        raise _ApiError(400, "identity id must be an integer") from None
    if identity_id <= 0:
        raise _ApiError(400, "identity id must be positive")

    if not request.app.state.mappings.revoke_identity(identity_id, username):
        raise _ApiError(404, "identity not found or already revoked")

    logger.info("identity revoked (%s, id=%s) from %s", username, identity_id, _client_ip(request))
    return JSONResponse({"ok": True, "username": username, "identity_id": identity_id})


async def update_identity_endpoint(request: Request) -> Response:
    _require_json(request)
    body = await request.json()
    if "label" not in body:
        raise _ApiError(400, "missing 'label'")
    label = body["label"]
    if label is not None and (not isinstance(label, str) or len(label) > 120):
        raise _ApiError(400, "label must be null or a string of at most 120 characters")
    label = label.strip() if isinstance(label, str) else None
    settings = get_settings()
    username = _authenticated_username(request, settings)
    try:
        identity_id = int(request.path_params["identity_id"])
    except (TypeError, ValueError):
        raise _ApiError(400, "identity id must be an integer") from None
    if identity_id <= 0:
        raise _ApiError(400, "identity id must be positive")

    identity = request.app.state.mappings.update_identity_label(identity_id, username, label or None)
    if identity is None:
        raise _ApiError(404, "identity not found or revoked")
    logger.info("identity label updated (%s, id=%s) from %s", username, identity_id, _client_ip(request))
    return JSONResponse({"ok": True, "username": username, "identity": _identity_json(identity)})


async def nostr_json_endpoint(request: Request) -> Response:
    """NIP-05: https://<domain>/.well-known/nostr.json?name=<username>

    The one way this project exposes a linked identity for use *outside*
    YunoHost entirely - any Nostr client, not just other apps on this
    server - without touching LDAP or anything else PLAN.md's Phase 4
    deliberately deferred. Only ever reveals a mapping for a username that
    has actually linked a pubkey (opt-in by definition of having linked
    one at all) and only when queried by that exact name, matching how
    every other NIP-05 provider behaves - this never lists all linked
    users at once.
    """
    name = request.query_params.get("name")
    names: dict[str, str] = {}

    if name:
        mappings: MappingStore = request.app.state.mappings
        identity = mappings.get_by_username(name)
        if identity is not None and identity.enabled:
            names[name] = identity.pubkey

    # NIP-05 verification happens from an arbitrary Nostr client's own
    # origin, so this - unlike every other route here - has to be
    # readable cross-origin.
    return JSONResponse({"names": names}, headers={"Access-Control-Allow-Origin": "*"})


async def nostr_login_page(request: Request) -> Response:
    return HTMLResponse(render_login_page(), headers={"Content-Security-Policy": CONTENT_SECURITY_POLICY})


async def nostr_account_page(request: Request) -> Response:
    return HTMLResponse(render_account_page(), headers={"Content-Security-Policy": CONTENT_SECURITY_POLICY})


async def static_asset(request: Request) -> Response:
    filename = request.path_params["filename"]
    try:
        content_type = content_type_for_static_asset(filename)
    except KeyError:
        raise _ApiError(404, "not found") from None
    return Response(read_static_asset(filename), media_type=content_type)


async def _api_error_handler(request: Request, exc: _ApiError) -> Response:
    return JSONResponse({"error": exc.message}, status_code=exc.status_code)


async def root_redirect(request: Request) -> Response:
    # This app has no permission.main.path setting (packaging_format 2's
    # single install.domain question always installs it at the domain's
    # root, "/"), so unlike apps installed under a subpath, its own
    # /nostr-login etc. routes don't automatically "fill in" what a visitor
    # hitting the bare domain sees - with no route for "/" at all, that 404s.
    # Confirmed live: navigating straight to a domain nostr_auth is
    # installed on returns "not found", while /nostr-login itself works.
    #
    # Check for an already-valid YunoHost session first (the same check
    # /identity uses) so a user who's already signed in - via Nostr or
    # password - lands straight on the portal instead of being sent through
    # /nostr-login again on every single visit to the bare domain.
    cookie_header = request.headers.get("cookie")
    if cookie_header:
        settings = get_settings()
        try:
            portal_client.get_authenticated_username(
                cookie_header,
                host=request.headers.get("host", ""),
                base_url=settings.portal_api_base_url,
            )
        except portal_client.PortalAuthError:
            pass
        else:
            return RedirectResponse("/yunohost/sso/")

    return RedirectResponse("/nostr-login")


def create_app() -> Starlette:
    settings = get_settings()

    routes = [
        Route("/", root_redirect, methods=["GET"]),
        Route("/nostr-login", nostr_login_page, methods=["GET"]),
        Route("/nostr-account", nostr_account_page, methods=["GET"]),
        Route("/nostr-admin", admin_page, methods=["GET"]),
        Route("/static/{filename}", static_asset, methods=["GET"]),
        Route("/challenge", challenge_endpoint, methods=["GET"]),
        Route("/authenticate", authenticate_endpoint, methods=["POST"]),
        Route("/link/challenge", link_challenge_endpoint, methods=["POST"]),
        Route("/link", link_endpoint, methods=["POST"]),
        Route("/unlink", unlink_endpoint, methods=["POST"]),
        Route("/identity", identity_endpoint, methods=["GET"]),
        Route("/identities", identities_endpoint, methods=["GET"]),
        Route("/identities/link", add_identity_endpoint, methods=["POST"]),
        Route("/identities/{identity_id}", update_identity_endpoint, methods=["PATCH"]),
        Route("/identities/{identity_id}", revoke_identity_endpoint, methods=["DELETE"]),
        Route("/policy", policy_endpoint, methods=["GET"]),
        Route("/nostr-admin/api/session", admin_session_endpoint, methods=["GET"]),
        Route("/nostr-admin/api/identities", admin_list_identities_endpoint, methods=["GET"]),
        Route("/nostr-admin/api/identities", admin_add_identity_endpoint, methods=["POST"]),
        Route(
            "/nostr-admin/api/identities/{identity_id}/revoke",
            admin_revoke_identity_endpoint,
            methods=["POST"],
        ),
        Route(
            "/nostr-admin/api/identities/{identity_id}/rename",
            admin_rename_identity_endpoint,
            methods=["POST"],
        ),
        Route("/nostr-admin/api/identities/unlink", admin_unlink_endpoint, methods=["POST"]),
        Route("/.well-known/nostr.json", nostr_json_endpoint, methods=["GET"]),
    ]

    app = Starlette(routes=routes, exception_handlers={_ApiError: _api_error_handler})
    app.state.challenge_store = ChallengeStore(
        ttl_seconds=settings.challenge_ttl_seconds,
        db_path=settings.challenge_db_path,
    )
    app.state.mappings = MappingStore(settings.mappings_db_path)
    return app


def _configure_logging(settings: Settings) -> None:
    # Without this, nothing below WARNING ever reaches a handler (Python's
    # logging "handler of last resort" only emits WARNING+), which
    # silently dropped every audit-log line PLAN.md Phase 13 asks for
    # (login success, identity linked, etc. are all .info() calls) even
    # though the code looked like it was already logging them.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if settings.security_log_path is not None:
        # PLAN.md Phase 13's "rate limiting, brute-force throttling":
        # nostr_auth_ynh wires ynh_config_add_fail2ban to watch this exact
        # file for the "... failure from <ip>: ..." lines server.py's
        # endpoint handlers emit through `logger`.
        handler = logging.FileHandler(settings.security_log_path)
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)


def main() -> None:
    import uvicorn

    _configure_logging(get_settings())
    uvicorn.run(create_app(), host="127.0.0.1", port=8766)


if __name__ == "__main__":
    main()
