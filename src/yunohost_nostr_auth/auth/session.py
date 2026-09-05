"""Bridge into YunoHost's own session creation (PLAN.md Phase 1).

The open question this module exists to answer, before any of it is
implemented: does YunoHost 12's portal API / SSOwat expose an internal
callable login function this service can invoke directly, or does session
creation have to be replicated (cookie format, signing mechanism and secret
location, server-side session state, expiry/refresh, logout, CSRF)?

Findings go in PHASE0_INVESTIGATION.md at the repo root. Prefer invoking
YunoHost's own code; replicating session internals is the fallback.
"""

from __future__ import annotations


def create_ynh_session(ynh_username: str):
    raise NotImplementedError("Blocked on Phase 1 investigation - see PHASE0_INVESTIGATION.md")
