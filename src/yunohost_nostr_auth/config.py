"""Runtime settings, read from `NOSTR_AUTH_*` environment variables.

`data_dir` matches the `NOSTR_AUTH_DATA_DIR` variable already set by
nostr_auth_ynh's conf/systemd.service, so the two repos agree on this
without either hardcoding a path the other has to know about.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NOSTR_AUTH_")

    data_dir: Path = Path("./data")
    portal_api_base_url: str = "http://127.0.0.1:6788"

    # PLAN.md Phase 3: 30-120 second expiry.
    challenge_ttl_seconds: int = 90
    # Slack for the signed event's own created_at vs. the challenge's
    # issued_at/expires_at window, to allow for client/server clock drift
    # without materially widening the replay window (the single-use nonce
    # is what actually prevents replay).
    clock_skew_seconds: int = 60

    # ynh/sessions.py talks to the long-running, ynh-portal-owned
    # mint_session_server.py over this Unix socket to mint a real
    # yunohost.portal session (PHASE0_INVESTIGATION.md's "Privilege-drop
    # redesign" - a sudo-spawned-per-request helper doesn't work in
    # containerized installs where the container sets no_new_privs).
    mint_session_socket: Path = Path("/run/nostr_auth-mint/mint.sock")
    identity_lookup_socket: Path = Path("/run/nostr_auth-lookup/lookup.sock")

    # Relay-list lookup (identity/relays.py, ynh/relay_lookup_server.py):
    # answers "what relays does this linked user prefer" for local
    # consumers such as nostr_catalog, by fetching the linked pubkey's own
    # NIP-65 (kind 10002) event. Shares identity_lookup's socket/group by
    # default - same trust boundary, same consumers - but is independently
    # configurable since it's a separate service with its own lifecycle.
    relay_lookup_socket: Path = Path("/run/nostr_auth-lookup/relays.sock")
    relay_lookup_group: str = "nostr-auth-lookup"
    # Comma-separated bootstrap relays used only to *discover* a pubkey's
    # own relay list - same pattern as nostr_blog's `fallback_relays`
    # install question.
    relay_bootstrap_relays: str = "wss://relay.damus.io,wss://nos.lol"
    relay_fetch_timeout_seconds: float = 8.0
    # A fetch happens at most this often per pubkey; cheaper reads in
    # between are served from relay_cache.py's cache, stale or not -
    # NIP-65 doesn't change often enough to justify a shorter TTL.
    relay_cache_ttl_seconds: int = 3600

    # PLAN.md Phase 13: "rate limiting, brute-force throttling." Rather
    # than reimplement IP banning in Python, this writes a dedicated,
    # fail2ban-parseable log of auth/link failures (each line includes the
    # requesting IP - see server.py's _client_ip) that nostr_auth_ynh's
    # conf/systemd.service (LogsDirectory=) and ynh_config_add_fail2ban
    # jail/filter watch. None (the default) disables the extra file
    # handler entirely - e.g. in tests, or a non-YunoHost deployment that
    # wants its own throttling instead.
    security_log_path: Path | None = None

    @property
    def mappings_db_path(self) -> Path:
        return self.data_dir / "identities.db"

    @property
    def relay_cache_db_path(self) -> Path:
        return self.data_dir / "relays.db"

    @property
    def relay_bootstrap_relay_list(self) -> list[str]:
        return [relay.strip() for relay in self.relay_bootstrap_relays.split(",") if relay.strip()]


def get_settings() -> Settings:
    return Settings()
