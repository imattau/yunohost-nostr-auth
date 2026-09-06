"""Private, read-only relay-list lookup service.

Answers exactly one question for one pubkey: "what relays does this
*linked* user's own NIP-65 (kind 10002) event advertise" - see
identity/relays.py's docstring for why an unlinked pubkey is refused
rather than resolved (this must not become an open relay-list oracle for
arbitrary pubkeys). Consumer authorization is enforced the same way as
identity_lookup_server.py: the socket's filesystem group plus SO_PEERCRED
membership checking.

A cache miss triggers a live NIP-65 fetch inline, so a caller's first
lookup for a given pubkey pays the fetch's full latency (bounded by
Settings.relay_fetch_timeout_seconds); every lookup after that, until the
cache entry expires, is a local SQLite read.
"""

from __future__ import annotations

import argparse
import asyncio
import grp
import json
import logging
import os
import socketserver
from pathlib import Path

from yunohost_nostr_auth.config import get_settings
from yunohost_nostr_auth.identity import relays
from yunohost_nostr_auth.identity.mappings import MappingStore
from yunohost_nostr_auth.identity.relay_cache import RelayCache
from yunohost_nostr_auth.ynh.identity_lookup_server import (
    DEFAULT_GROUP,
    _PUBKEY_RE,
    _peer_credentials,
    _read_line,
    _uid_in_group,
)

logger = logging.getLogger("yunohost_nostr_auth.relay_lookup_server")


def _resolve_relays(
    pubkey: str,
    *,
    mappings: MappingStore,
    cache: RelayCache,
    bootstrap_relays: list[str],
    fetch_timeout_seconds: float,
    cache_ttl_seconds: int,
) -> dict:
    identity = mappings.get_by_pubkey(pubkey)
    if identity is None:
        return {"linked": False, "relays": [], "fetched_at": None}

    cached = cache.get(pubkey)
    if cached is not None and cached.age_seconds() < cache_ttl_seconds:
        return _response(cached.relays, cached.fetched_at)

    try:
        fetched = asyncio.run(
            relays.fetch_relay_list(pubkey, bootstrap_relays=bootstrap_relays, timeout_seconds=fetch_timeout_seconds)
        )
    except Exception as exc:  # noqa: BLE001 - a live fetch failure must not crash the service; fall back below
        logger.info("relay fetch failed for a linked pubkey: %s", exc)
        if cached is not None:
            return _response(cached.relays, cached.fetched_at)  # stale is better than nothing
        return {"linked": True, "relays": [], "fetched_at": None}

    cache.store(pubkey, fetched)
    refreshed = cache.get(pubkey)
    return _response(refreshed.relays, refreshed.fetched_at)


def _response(relay_entries, fetched_at: int) -> dict:
    return {
        "linked": True,
        "relays": [{"url": r.url, "read": r.read, "write": r.write} for r in relay_entries],
        "fetched_at": fetched_at,
    }


class _Handler(socketserver.BaseRequestHandler):
    server: "_Server"

    def handle(self) -> None:
        conn = self.request
        try:
            uid, gid = _peer_credentials(conn)
            if not _uid_in_group(uid, gid, self.server.allowed_group):
                self._respond({"error": "forbidden"})
                return
            request = json.loads(_read_line(conn))
            pubkey = request["pubkey"]
            if set(request) != {"pubkey"} or not isinstance(pubkey, str) or not _PUBKEY_RE.fullmatch(pubkey):
                raise ValueError("pubkey must be 64 lowercase hexadecimal characters")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            self._respond({"error": f"bad request: {exc}"})
            return

        try:
            payload = _resolve_relays(
                pubkey,
                mappings=self.server.mappings,
                cache=self.server.cache,
                bootstrap_relays=self.server.bootstrap_relays,
                fetch_timeout_seconds=self.server.fetch_timeout_seconds,
                cache_ttl_seconds=self.server.cache_ttl_seconds,
            )
            self._respond(payload)
        except Exception as exc:  # pragma: no cover - defensive service boundary
            logger.info("relay lookup failed: %s", exc)
            self._respond({"error": "lookup failed"})

    def _respond(self, payload: dict) -> None:
        self.request.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        socket_path,
        mappings: MappingStore,
        cache: RelayCache,
        allowed_group: str,
        *,
        bootstrap_relays: list[str],
        fetch_timeout_seconds: float,
        cache_ttl_seconds: int,
    ) -> None:
        self.mappings = mappings
        self.cache = cache
        self.allowed_group = allowed_group
        self.bootstrap_relays = bootstrap_relays
        self.fetch_timeout_seconds = fetch_timeout_seconds
        self.cache_ttl_seconds = cache_ttl_seconds
        super().__init__(str(socket_path), _Handler)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description=__doc__)
    settings = get_settings()
    parser.add_argument("--socket-path", type=Path, default=settings.relay_lookup_socket)
    parser.add_argument("--group", default=settings.relay_lookup_group or DEFAULT_GROUP)
    args = parser.parse_args(argv)

    args.socket_path.parent.mkdir(parents=True, exist_ok=True)
    args.socket_path.unlink(missing_ok=True)
    server = _Server(
        args.socket_path,
        MappingStore(settings.mappings_db_path),
        RelayCache(settings.relay_cache_db_path),
        args.group,
        bootstrap_relays=settings.relay_bootstrap_relay_list,
        fetch_timeout_seconds=settings.relay_fetch_timeout_seconds,
        cache_ttl_seconds=settings.relay_cache_ttl_seconds,
    )
    args.socket_path.chmod(0o660)
    try:
        os.chown(args.socket_path, -1, grp.getgrnam(args.group).gr_gid)
    except KeyError as exc:
        server.server_close()
        args.socket_path.unlink(missing_ok=True)
        raise SystemExit(f"lookup group does not exist: {args.group}") from exc
    logger.info("relay lookup listening on %s", args.socket_path)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        args.socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
