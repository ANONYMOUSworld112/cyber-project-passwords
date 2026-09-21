"""Password recovery via hint question/answer.

The hint answer is hashed with a dedicated Argon2id (not the password
KDF) and stored inside ``hint_pub.enc``. ``hint_pub.enc`` is encrypted
with a key derived from the answer itself, so the file can be opened
without the password but cannot be opened without the answer.

Flow:

1. ``start_recovery(user, answer)`` derives an answer key, attempts to
   decrypt ``hint_pub.enc``. If the MAC fails, the answer is wrong.
2. If successful, the hint question is revealed. ``complete_recovery``
   confirms the answer and rewrites ``profile_pw.enc`` and ``vault.enc``
   under the new password.

Note on vault contents: the vault is encrypted with the password-derived
KEK, not the answer-derived key. Recovery without the password can
therefore reset the password but cannot decrypt the old vault. The
existing vault is replaced with an empty one. This matches the spec's
"if both are forgotten, data is lost" semantics and prevents the hint
answer from being a backdoor to vault contents.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from csp.auth.lockout import (
    check_lock,
    register_failure,
    register_success,
)
from csp.auth.password_check import (
    normalize_answer,
    validate_password,
    validate_username,
)
from csp.crypto.kdf import hash_answer
from csp.auth.users import (
    add_user_to_master,
    create_user_dirs,
    load_master,
    user_exists,
)
from csp.crypto.kdf import (
    KDFParams,
    derive_key_with_params,
    make_kdf_params,
)
from csp.crypto.memzero import SecretBuffer
from csp.crypto.vault_file import (
    _FILE_VERSION,
    _b64d,
    _b64e,
    write_vault_file,
)
from csp.errors import (
    AuthError,
    NotInitializedError,
    UserError,
)
from csp.io_utils.atomic_write import atomic_write_text
from csp.io_utils.fs_perms import private_file
from csp.paths import (
    hint_pub_file,
    profile_pw_file,
    vault_file,
)


_ANSWER_KDF = {"alg": "argon2id", "t": 2, "m": 19456, "p": 1}


def _answer_kdf_params() -> KDFParams:
    import base64
    return KDFParams(
        alg="argon2id",
        t=_ANSWER_KDF["t"],
        m=_ANSWER_KDF["m"],
        p=_ANSWER_KDF["p"],
        salt_b64=base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("="),
    )


def _derive_answer_key(answer: str, params: KDFParams) -> bytes:
    import base64
    pad = "=" * (-len(params.salt_b64) % 4)
    salt = base64.urlsafe_b64decode((params.salt_b64 + pad).encode("ascii"))
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=answer.encode("utf-8"),
        salt=salt,
        time_cost=params.t,
        memory_cost=params.m,
        parallelism=params.p,
        hash_len=32,
        type=Type.ID,
    )


def _make_profile_pw_payload() -> dict:
    return {"v": _FILE_VERSION, "kind": "profile_pw"}


def _empty_vault_payload() -> dict:
    return {
        "v": _FILE_VERSION,
        "credentials": [],
        "incidents": [],
        "fim": {"baseline": {}, "watched_paths": []},
        "hashdb": {"known_malicious": {}, "known_clean": {}},
        "logs_runs": [],
    }


def write_initial_blobs(
    username: str,
    password: str,
    hint_question: str,
    hint_answer: str,
) -> None:
    """Write profile_pw.enc, hint_pub.enc, and vault.enc for a new user.

    Overwrites existing files. Called by first-time setup and by
    ``complete_recovery``.
    """
    if validate_username(username) is not None:
        raise UserError(f"invalid username: {username}")
    if validate_password(password, username) is not None:
        raise UserError("password does not meet policy")
    if not hint_question.strip():
        raise UserError("hint question must not be empty")
    norm_answer = normalize_answer(hint_answer)
    if not norm_answer:
        raise UserError("hint answer must not be empty")

    create_user_dirs(username)

    pw_kdf = make_kdf_params()
    pw_key = SecretBuffer(derive_key_with_params(password, pw_kdf))
    try:
        write_vault_file(
            profile_pw_file(username),
            _make_profile_pw_payload(),
            pw_kdf,
            pw_key.get(),
        )
        write_vault_file(
            vault_file(username),
            _empty_vault_payload(),
            pw_kdf,
            pw_key.get(),
        )
    finally:
        pw_key.wipe()

    answer_kdf = _answer_kdf_params()
    answer_key = SecretBuffer(_derive_answer_key(norm_answer, answer_kdf))
    try:
        answer_hash = hash_answer(norm_answer)
        payload = {
            "hint_question": hint_question.strip(),
            "answer_hash": answer_hash,
        }
        plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
        env = {
            "v": _FILE_VERSION,
            "kdf_answer": answer_kdf.to_dict(),
            "nonce": "",
            "ct": "",
        }
        aad = json.dumps(env, sort_keys=True, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)
        ct_tag = AESGCM(answer_key.get()).encrypt(nonce, plaintext, aad)
        env["nonce"] = _b64e(nonce)
        env["ct"] = _b64e(ct_tag)
        atomic_write_text(
            hint_pub_file(username),
            json.dumps(env, indent=2, sort_keys=True),
        )
        private_file(hint_pub_file(username))
    finally:
        answer_key.wipe()

    if not user_exists(username):
        add_user_to_master(username)


# --- Recovery operations --------------------------------------------

@dataclass
class RecoveryContext:
    username: str
    hint_question: str


def _verify_answer(username: str, answer: str) -> dict:
    """Verify ``answer`` against the stored hint and return the payload.

    Raises :class:`AuthError` on failure.
    """
    norm = normalize_answer(answer)
    if not norm:
        raise AuthError("hint answer must not be empty")

    path = hint_pub_file(username)
    if not path.exists():
        raise UserError("recovery data is missing; cannot recover this account")

    try:
        env = json.loads(path.read_text(encoding="utf-8"))
        answer_kdf = KDFParams.from_dict(env["kdf_answer"])
        nonce = _b64d(env["nonce"])
        ct = _b64d(env["ct"])
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise UserError(f"recovery file is corrupt: {e}") from e

    answer_key = SecretBuffer(_derive_answer_key(norm, answer_kdf))
    try:
        aad_env = {
            "v": int(env["v"]),
            "kdf_answer": answer_kdf.to_dict(),
            "nonce": "",
            "ct": "",
        }
        aad = json.dumps(aad_env, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            plaintext = AESGCM(answer_key.get()).decrypt(nonce, ct, aad)
        except InvalidTag as e:
            register_failure(username)
            raise AuthError("hint answer is incorrect") from e
    finally:
        answer_key.wipe()

    try:
        return json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise UserError(f"recovery payload invalid: {e}") from e


def start_recovery(username: str, answer: str) -> RecoveryContext:
    """Begin recovery: verify the answer and reveal the hint question."""
    if not load_master().users:
        raise NotInitializedError("application is not initialized")
    if not user_exists(username):
        raise UserError(f"unknown user: {username}")
    check_lock(username)

    payload = _verify_answer(username, answer)
    register_success(username)
    return RecoveryContext(
        username=username,
        hint_question=str(payload.get("hint_question", "")),
    )


def complete_recovery(
    ctx: RecoveryContext,
    answer: str,
    new_password: str,
) -> None:
    """Confirm the answer and reset the password.

    The hint answer is re-verified to ensure the operator still has the
    secret. The new password is then used to derive a fresh KEK and
    rewrite both ``profile_pw.enc`` and ``vault.enc``. The vault is
    reset to empty; old contents are not recoverable (we don't have
    the old password).
    """
    payload = _verify_answer(ctx.username, answer)
    hint_question = str(payload.get("hint_question", ""))

    if validate_password(new_password, ctx.username) is not None:
        raise UserError("new password does not meet policy")

    write_initial_blobs(
        username=ctx.username,
        password=new_password,
        hint_question=hint_question,
        hint_answer=answer,
    )
