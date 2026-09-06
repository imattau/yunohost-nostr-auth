import asyncio
import json

import pytest
from nostr_sdk import EventBuilder, Keys, Kind, Tag
from starlette.requests import Request
from pydantic import ValidationError

from yunohost_nostr_auth import server as server_module
from yunohost_nostr_auth.config import Settings
from yunohost_nostr_auth.ynh import portal_client


DOMAIN = "example.org"


def _request(app, method, path, *, body=None, cookie=None, path_params=None):
    raw_body = b"" if body is None else json.dumps(body).encode()
    headers = [(b"host", DOMAIN.encode())]
    if body is not None:
        headers.append((b"content-type", b"application/json"))
    if cookie:
        headers.append((b"cookie", cookie.encode()))

    async def receive():
        return {"type": "http.request", "body": raw_body, "more_body": False}

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": b"",
        "path_params": path_params or {},
        "app": app,
    }
    return Request(scope, receive)


def _json_response(response):
    return json.loads(response.body)


def _sign(keys: Keys, challenge: dict) -> dict:
    builder = EventBuilder(Kind(challenge["kind"]), "").tags(
        [
            Tag.parse(["challenge", challenge["nonce"]]),
            Tag.parse(["domain", challenge["domain"]]),
            Tag.parse(["action", challenge["action"]]),
        ]
    )
    return json.loads(builder.finalize(keys).as_json())


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NOSTR_AUTH_DATA_DIR", str(tmp_path))
    return server_module.create_app()


def _add_identity(app, keys, *, cookie="yunohost.portal=valid"):
    challenge_response = asyncio.run(
        server_module.link_challenge_endpoint(
            _request(app, "POST", "/link/challenge")
        )
    )
    challenge = _json_response(challenge_response)
    event = _sign(keys, challenge)
    return asyncio.run(
        server_module.add_identity_endpoint(
            _request(
                app,
                "POST",
                "/identities/link",
                body={
                    "event": event,
                    "signer_type": "passkey",
                    "label": "Laptop",
                },
                cookie=cookie,
            )
        )
    )


def test_add_list_and_revoke_identity_handlers(app, monkeypatch):
    monkeypatch.setattr(
        portal_client, "get_authenticated_username", lambda cookie_header, **kw: "matt"
    )
    keys = Keys.generate()

    added = _add_identity(app, keys)
    assert added.status_code == 200
    added_body = _json_response(added)
    assert added_body["identity"]["signer_type"] == "passkey"
    assert added_body["identity"]["label"] == "Laptop"
    identity_id = added_body["identity"]["id"]

    listed = asyncio.run(
        server_module.identities_endpoint(
            _request(app, "GET", "/identities", cookie="yunohost.portal=valid")
        )
    )
    assert _json_response(listed)["identities"][0]["id"] == identity_id

    renamed = asyncio.run(
        server_module.update_identity_endpoint(
            _request(
                app,
                "PATCH",
                f"/identities/{identity_id}",
                body={"label": "Work laptop"},
                cookie="yunohost.portal=valid",
                path_params={"identity_id": str(identity_id)},
            )
        )
    )
    assert _json_response(renamed)["identity"]["label"] == "Work laptop"

    revoked = asyncio.run(
        server_module.revoke_identity_endpoint(
            _request(
                app,
                "DELETE",
                f"/identities/{identity_id}",
                cookie="yunohost.portal=valid",
                path_params={"identity_id": str(identity_id)},
            )
        )
    )
    assert revoked.status_code == 200
    assert app.state.mappings.get_by_id(identity_id).enabled is False


def test_add_without_cookie_does_not_consume_challenge(app):
    challenge = app.state.challenge_store.issue(DOMAIN, "yunohost-link")
    keys = Keys.generate()
    event = _sign(
        keys,
        {
            "kind": server_module.nostr_verify.CHALLENGE_EVENT_KIND,
            "nonce": challenge.nonce,
            "domain": challenge.domain,
            "action": challenge.action,
        },
    )

    with pytest.raises(server_module._ApiError) as error:
        asyncio.run(
            server_module.add_identity_endpoint(
                _request(
                    app,
                    "POST",
                    "/identities/link",
                    body={"event": event},
                )
            )
        )

    assert error.value.status_code == 401
    assert app.state.challenge_store.consume(challenge.nonce) is not None


def test_public_policy_reports_defaults(app):
    response = asyncio.run(server_module.policy_endpoint(_request(app, "GET", "/policy")))

    assert response.status_code == 200
    assert _json_response(response) == {
        "allow_nostr_login": True,
        "allow_identity_linking": True,
    }


def test_policy_can_disable_login_without_deleting_identities(app, monkeypatch):
    app.state.mappings.link("matt", "a" * 64)
    monkeypatch.setenv("NOSTR_AUTH_ALLOW_NOSTR_LOGIN", "false")

    with pytest.raises(server_module._ApiError) as error:
        asyncio.run(server_module.challenge_endpoint(_request(app, "GET", "/challenge")))

    assert error.value.status_code == 403
    assert app.state.mappings.get_by_username("matt") is not None


def test_policy_can_disable_self_service_linking(monkeypatch, app):
    monkeypatch.setenv("NOSTR_AUTH_ALLOW_IDENTITY_LINKING", "false")

    with pytest.raises(server_module._ApiError) as error:
        asyncio.run(server_module.link_challenge_endpoint(_request(app, "POST", "/link/challenge")))

    assert error.value.status_code == 403


def test_policy_endpoint_reflects_disabled_flags(app, monkeypatch):
    monkeypatch.setenv("NOSTR_AUTH_ALLOW_NOSTR_LOGIN", "0")
    monkeypatch.setenv("NOSTR_AUTH_ALLOW_IDENTITY_LINKING", "false")

    response = asyncio.run(server_module.policy_endpoint(_request(app, "GET", "/policy")))

    assert _json_response(response) == {
        "allow_nostr_login": False,
        "allow_identity_linking": False,
    }


def test_runtime_timing_settings_are_bounded():
    assert Settings(challenge_ttl_seconds=30, clock_skew_seconds=300).challenge_ttl_seconds == 30

    with pytest.raises(ValidationError):
        Settings(challenge_ttl_seconds=29)
    with pytest.raises(ValidationError):
        Settings(clock_skew_seconds=301)
