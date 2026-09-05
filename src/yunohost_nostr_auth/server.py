"""ASGI app wiring together the endpoints described in PLAN.md's Phase 2:

    GET  /challenge
    POST /authenticate
    POST /link/challenge
    POST /link
    POST /unlink
    GET  /identity

Runs on localhost only; Nginx (see the nostr_auth_ynh package) provides the
external route and TLS termination.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.routing import Route


def create_app() -> Starlette:
    # Route handlers land alongside the auth/ and identity/ modules as each
    # phase in PLAN.md is implemented - kept unimplemented here rather than
    # stubbed with fake responses, since Phase 1 (YunoHost session creation)
    # has to be resolved first.
    routes: list[Route] = []
    return Starlette(routes=routes)


def main() -> None:
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=8766)


if __name__ == "__main__":
    main()
