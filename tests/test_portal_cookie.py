import base64

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from yunohost_nostr_auth.ynh import portal_cookie

SECRET = "0123456789abcdef0123456789abcdef"[:32]


def _decrypt(data_enc_and_iv_b64: str, secret: str) -> bytes:
    data_enc_b64, iv_b64 = data_enc_and_iv_b64.split("|")
    data_enc = base64.b64decode(data_enc_b64)
    iv = base64.b64decode(iv_b64)

    alg = algorithms.AES(secret.encode())
    decryptor = Cipher(alg, modes.CBC(iv), default_backend()).decryptor()
    padded = decryptor.update(data_enc)
    unpadder = padding.PKCS7(alg.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def test_short_hash_is_deterministic():
    assert portal_cookie.short_hash("matt") == portal_cookie.short_hash("matt")
    assert portal_cookie.short_hash("matt") != portal_cookie.short_hash("alice")
    assert len(portal_cookie.short_hash("matt")) == 40  # hexdigest(20) -> 40 hex chars


def test_encrypt_empty_password_round_trips_to_empty_string():
    encrypted = portal_cookie.encrypt_empty_password(SECRET)
    assert "|" in encrypted
    assert _decrypt(encrypted, SECRET) == b""


def test_encrypt_empty_password_uses_a_fresh_iv_each_time():
    a = portal_cookie.encrypt_empty_password(SECRET)
    b = portal_cookie.encrypt_empty_password(SECRET)
    assert a != b


def test_mint_produces_a_verifiable_jwt_with_required_claims(tmp_path):
    session_folder = tmp_path / "sessions"
    session_folder.mkdir()

    minted = portal_cookie.mint(
        ynh_username="matt",
        host="example.org",
        email="matt@example.org",
        fullname="Matt Example",
        secret=SECRET,
        session_folder=session_folder,
    )

    # Matches the `options={"require": [...]}` set ldap_ynhuser.py's
    # get_session_cookie() enforces when reading the cookie back.
    claims = jwt.decode(minted.token, SECRET, algorithms=["HS256"], options={"require": ["id", "host", "user", "pwd"]})
    assert claims["user"] == "matt"
    assert claims["host"] == "example.org"
    assert claims["email"] == "matt@example.org"
    assert claims["fullname"] == "Matt Example"
    assert claims["id"] == minted.session_id
    assert claims["id"].startswith(portal_cookie.short_hash("matt"))

    assert (session_folder / minted.session_id).exists()
    assert minted.max_age == portal_cookie.SESSION_VALIDITY - 600


def test_mint_session_id_is_findable_by_invalidate_all_sessions_glob(tmp_path):
    """Mirrors ldap_ynhuser.py's invalidate_all_sessions_for_user(), which
    globs SESSION_FOLDER for `short_hash(user)*` - our minted session must
    still be found and revocable that way (e.g. on a password change).
    """
    session_folder = tmp_path / "sessions"
    session_folder.mkdir()

    minted = portal_cookie.mint(
        ynh_username="matt",
        host="example.org",
        email="matt@example.org",
        fullname="Matt Example",
        secret=SECRET,
        session_folder=session_folder,
    )

    matches = list(session_folder.glob(f"{portal_cookie.short_hash('matt')}*"))
    assert [p.name for p in matches] == [minted.session_id]


def test_wrong_secret_fails_verification(tmp_path):
    session_folder = tmp_path / "sessions"
    session_folder.mkdir()

    minted = portal_cookie.mint(
        ynh_username="matt",
        host="example.org",
        email="matt@example.org",
        fullname="Matt Example",
        secret=SECRET,
        session_folder=session_folder,
    )

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(minted.token, "fedcba9876543210fedcba9876543210"[:32], algorithms=["HS256"])
