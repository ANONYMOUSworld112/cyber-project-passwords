"""Login: derive a key from the password and load the user's vault.

This module is the only place that turns a typed password into an
in-memory key. It is used by the REPL's first prompt and by ``user add``
to verify a second user exists.
"""

from __future__ import annotations

import copy
from typing import Tuple

from csp.auth.lockout import (
    check_lock,
    register_failure,
    register_success,
)
from csp.auth.session import Session
from csp.auth.users import user_exists
from csp.crypto.kdf import KDFParams, derive_key_with_params
from csp.crypto.memzero import SecretBuffer
from csp.crypto.vault_file import VaultFile, read_vault_file
from csp.errors import AuthError, UserError, VaultError
from csp.paths import profile_pw_file, vault_file


def _read_kdf_from_profile_pw(username: str) -> KDFParams:
    """Read the KDF parameters from a profile_pw.enc *without* the key.

    The envelope stores KDF parameters in plaintext (outside the
    ciphertext), so we can load them and prepare to derive.
    """
    path = profile_pw_file(username)
    if not path.exists():
        raise UserError(f"user '{username}' has no profile; cannot unlock")
    text = path.read_text(encoding="utf-8")
    vf = VaultFile.from_json(text)
    return vf.kdf


def unlock(username: str, password: str) -> Tuple[Session, dict]:
    """Attempt to unlock ``username``'s vault.

    On success returns ``(session, vault_payload)``. The caller takes
    ownership of the session and is responsible for wiping it.

    On failure raises :class:`AuthError` and records a failed attempt
    against the user.
    """
    if not user_exists(username):
        raise UserError(f"unknown user: {username}")
    check_lock(username)

    kdf = _read_kdf_from_profile_pw(username)
    key_buf = SecretBuffer(derive_key_with_params(password, kdf))
    succeeded = False
    try:
        try:
            read_vault_file(profile_pw_file(username), key_buf.get())
        except VaultError as e:
            register_failure(username)
            raise AuthError("invalid password") from e
        try:
            payload = read_vault_file(vault_file(username), key_buf.get())
        except VaultError as e:
            register_failure(username)
            raise AuthError("vault is corrupt or unreadable") from e
        succeeded = True
    finally:
        if not succeeded:
            key_buf.wipe()

    register_success(username)
    session = Session(
        user=username,
        key=key_buf,
        kdf=kdf,
        _vault_cache=copy.deepcopy(payload),
    )
    return session, payload


def unlock_with_session_install(username: str, password: str) -> Tuple[Session, dict]:
    """Like :func:`unlock` but installs the session globally."""
    from csp.auth.session import set_session
    session, payload = unlock(username, password)
    set_session(session)
    return session, payload
