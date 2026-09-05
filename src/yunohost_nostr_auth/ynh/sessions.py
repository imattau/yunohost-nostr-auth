"""Thin wrapper over auth/session.py's YunoHost session establishment,
scoped to this module so ynh/permissions.py can restrict exactly what the
service account is allowed to call.
"""

from __future__ import annotations
