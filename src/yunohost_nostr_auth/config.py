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

    @property
    def mappings_db_path(self) -> Path:
        return self.data_dir / "identities.db"


def get_settings() -> Settings:
    return Settings()
