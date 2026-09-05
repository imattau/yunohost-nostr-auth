"""Loads the static `/nostr-login` page (PLAN.md Phase 6/7).

The page itself does all the work client-side against this daemon's own
JSON API (GET /challenge, POST /authenticate) - this module just serves
the static HTML, once, cached.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources

# PLAN.md Phase 13: "strict CSP on Nostr login page." Matches the policy
# YunoHost's own nginx config applies to /yunohost/sso/ (see
# PHASE0_INVESTIGATION.md) - same shape, since this page has the same
# threat model (a login surface).
CONTENT_SECURITY_POLICY = (
    "upgrade-insecure-requests; default-src 'self'; "
    "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
    "object-src 'none'; img-src 'self' data:;"
)


@lru_cache(maxsize=1)
def render_login_page() -> str:
    return resources.files(__package__).joinpath("nostr_login.html").read_text()
