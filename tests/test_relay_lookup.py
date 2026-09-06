from __future__ import annotations

import asyncio
import json
import os
import socket
import threading

from nostr_sdk import EventBuilder, Keys, Kind, LocalRelayBuilder, Tag

from yunohost_nostr_auth.identity.mappings import Identity
from yunohost_nostr_auth.identity.relay_cache import RelayCache
from yunohost_nostr_auth.identity.relays import RELAY_LIST_KIND
from yunohost_nostr_auth.ynh import relay_lookup, relay_lookup_server

PUBKEY = "a" * 64


class _Mappings:
    def __init__(self, identity=None):
        self.identity = identity

    def get_by_pubkey(self, pubkey):
        return self.identity if self.identity is not None and self.identity.pubkey == pubkey else None


def _request(socket_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(socket_path))
        sock.sendall(json.dumps(payload).encode() + b"\n")
        raw = b""
        while not raw.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
        return json.loads(raw)


def _start(tmp_path, mappings, monkeypatch, *, bootstrap_relays=None):
    monkeypatch.setattr(
        relay_lookup_server.grp,
        "getgrnam",
        lambda name: type("Group", (), {"gr_gid": os.getgid(), "gr_mem": []})(),
    )
    path = tmp_path / "relays.sock"
    server = relay_lookup_server._Server(
        path,
        mappings,
        RelayCache(tmp_path / "relays.db"),
        "nostr-auth-lookup",
        bootstrap_relays=bootstrap_relays or [],
        fetch_timeout_seconds=2,
        cache_ttl_seconds=3600,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return path, server, thread


def test_unlinked_pubkey_is_refused_not_resolved(tmp_path, monkeypatch):
    """An unlinked pubkey must not become an open relay-list oracle."""
    path, server, thread = _start(tmp_path, _Mappings(), monkeypatch)
    try:
        assert _request(path, {"pubkey": PUBKEY}) == {"linked": False, "relays": [], "fetched_at": None}
        result = relay_lookup.lookup_relays(PUBKEY, socket_path=path)
        assert result.linked is False
        assert result.relays == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_rejects_extra_fields_and_bad_pubkeys(tmp_path, monkeypatch):
    path, server, thread = _start(tmp_path, _Mappings(), monkeypatch)
    try:
        assert "error" in _request(path, {"pubkey": PUBKEY, "extra": True})
        assert "error" in _request(path, {"pubkey": PUBKEY.upper()})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_linked_pubkey_with_no_published_relay_list_returns_empty(tmp_path, monkeypatch):
    identity = Identity("codex", PUBKEY, 1, 2, True)
    path, server, thread = _start(tmp_path, _Mappings(identity), monkeypatch, bootstrap_relays=[])
    try:
        response = _request(path, {"pubkey": PUBKEY})
        assert response["linked"] is True
        assert response["relays"] == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


class _RunningLocalRelay:
    """A LocalRelay kept alive on its own persistent background-thread
    event loop for the lifetime of a test.

    asyncio.run() tears down its loop the moment the coroutine it drove
    returns, which would kill the relay right after publishing to it -
    the server's own later fetch (triggered from yet another thread, via
    its own fresh asyncio.run() call) needs the relay still listening.
    Connecting *to* the relay never needs to share this loop: it's a real
    OS-level connection to a bound port, so every other asyncio.run() call
    in this test (the publish step, and relay_lookup_server's internal
    fetch) works against it independently and normally.
    """

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.url: str | None = None
        ready = threading.Event()

        def _run() -> None:
            asyncio.set_event_loop(self.loop)
            relay = LocalRelayBuilder().build()
            self.loop.create_task(relay.run())
            self.url = self.loop.run_until_complete(self._wait_for_url(relay))
            ready.set()
            self.loop.run_forever()

        self.thread = threading.Thread(target=_run, daemon=True)
        self.thread.start()
        ready.wait(timeout=5)

    @staticmethod
    async def _wait_for_url(relay) -> str:
        await asyncio.sleep(0.2)
        return await relay.url()

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=2)


def test_linked_pubkey_fetches_and_then_serves_from_cache(tmp_path, monkeypatch):
    """End to end: a real published NIP-65 event on a real (in-process)
    relay, fetched live on the first lookup, then served from the cache
    without hitting the relay again."""
    relay = _RunningLocalRelay()
    try:
        keys = Keys.generate()
        unsigned = (
            EventBuilder(Kind(RELAY_LIST_KIND), "")
            .tags([Tag.parse(["r", "wss://relay.example"])])
            .finalize_unsigned(keys.public_key())
        )
        event = keys.sign_event(unsigned)

        async def _publish() -> None:
            from nostr_sdk import Client

            publisher = Client()
            await publisher.add_relay(relay.url)
            await publisher.connect()
            await asyncio.sleep(0.3)
            await publisher.send_event(event)
            await publisher.shutdown()

        asyncio.run(_publish())

        pubkey_hex = keys.public_key().to_hex()
        identity = Identity("codex", pubkey_hex, 1, 2, True)
        path, server, thread = _start(tmp_path, _Mappings(identity), monkeypatch, bootstrap_relays=[relay.url])
        try:
            first = _request(path, {"pubkey": pubkey_hex})
            assert first["linked"] is True
            assert first["relays"] == [{"url": "wss://relay.example", "read": True, "write": True}]

            cached = RelayCache(tmp_path / "relays.db").get(pubkey_hex)
            assert cached is not None
            assert cached.relays[0].url == "wss://relay.example"

            second = _request(path, {"pubkey": pubkey_hex})
            assert second == first
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
    finally:
        relay.stop()
