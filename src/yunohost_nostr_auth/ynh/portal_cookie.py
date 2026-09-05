"""Reproduces the exact `yunohost.portal` JWT + session-file shape that
`src/authenticators/ldap_ynhuser.py`'s `Authenticator.set_session_cookie()`
produces, so a session we mint is indistinguishable from one YunoHost's own
portal API would have minted - and so YunoHost's own
`invalidate_all_sessions_for_user()` (e.g. on password change) still finds
and revokes it.

Read from YunoHost 12.1.41.2 (commit c206fff7) - see
PHASE0_INVESTIGATION.md. This is the one piece of this project that
deliberately duplicates upstream logic rather than calling it (Phase 1's
documented fallback), specifically because `set_session_cookie()` needs a
live Bottle request/response context that doesn't exist outside
yunohost-portal-api's own process. Re-diff this module against
`src/authenticators/ldap_ynhuser.py` on every YunoHost core version bump -
if that file's cookie/session shape changes, this one silently stops being
invalidated correctly by password changes, or stops being accepted by
SSOwat at all.

Only ever invoked from mint_session_helper.py, which runs as the
`ynh-portal` system user - the only account that can read
SESSION_SECRET_PATH or write into SESSION_FOLDER. Nothing in the main
yunohost-nostr-auth daemon imports this module.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SESSION_SECRET_PATH = Path("/etc/yunohost/.ssowat_cookie_secret")
SESSION_FOLDER = Path("/var/cache/yunohost-portal/sessions")
SESSION_VALIDITY = 3 * 24 * 3600  # 3 days - matches ldap_ynhuser.py exactly
COOKIE_NAME = "yunohost.portal"


def read_session_secret(path: Path = SESSION_SECRET_PATH) -> str:
    return path.read_text().strip()


def short_hash(data: str) -> str:
    """Identical to ldap_ynhuser.py's short_hash - must match exactly so
    `invalidate_all_sessions_for_user()` (glob on `short_hash(user)*`)
    finds sessions we minted too.
    """
    return hashlib.shake_256(data.encode()).hexdigest(20)


def encrypt_empty_password(secret: str) -> str:
    """The `pwd` claim, AES-256-CBC-encrypted like ldap_ynhuser.py's
    `encrypt()`, but of an empty string - we never have the user's real
    LDAP password (PHASE0_INVESTIGATION.md's Conclusions). Format matches
    exactly (`<b64 ciphertext>|<b64 iv>`) so SSOwat's Lua side can still
    parse it (and get an empty password back) rather than erroring.
    """
    alg = algorithms.AES(secret.encode())
    iv = os.urandom(int(alg.block_size / 8))

    encryptor = Cipher(alg, modes.CBC(iv), default_backend()).encryptor()
    padder = padding.PKCS7(alg.block_size).padder()
    padded = padder.update(b"") + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return f"{base64.b64encode(ciphertext).decode()}|{base64.b64encode(iv).decode()}"


@dataclass(frozen=True)
class MintedSession:
    token: str
    session_id: str
    max_age: int


def mint(
    *,
    ynh_username: str,
    host: str,
    email: str,
    fullname: str,
    secret: str,
    session_folder: Path = SESSION_FOLDER,
) -> MintedSession:
    """Build the JWT and touch the session file. Caller (the CLI helper)
    is responsible for actually running as `ynh-portal` - this function
    does no privilege checks of its own, it just does the crypto/IO.
    """
    session_id = short_hash(ynh_username) + secrets.token_hex(10)

    claims = {
        "id": session_id,
        "host": host,
        "user": ynh_username,
        "pwd": encrypt_empty_password(secret),
        "email": email,
        "fullname": fullname,
    }
    token = jwt.encode(claims, secret, algorithm="HS256")

    session_file = session_folder / session_id
    session_file.touch(exist_ok=True)

    return MintedSession(token=token, session_id=session_id, max_age=SESSION_VALIDITY - 600)
