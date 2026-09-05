"""Least-privilege boundary between this service and YunoHost internals.

The service user must only be able to look up existing YunoHost users and
establish sessions for them - never general root access. Whatever mechanism
Phase 1 settles on for session creation, its required capability set is
documented and enforced here (e.g. via systemd sandboxing in the
nostr_auth_ynh package, or a narrow sudoers/helper boundary).
"""

from __future__ import annotations
