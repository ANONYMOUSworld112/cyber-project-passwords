"""Argon2id key derivation.

The parameters below are the *floor*. Servers and personal machines
made in the last several years can comfortably afford them. On a
modern laptop ``m=64 MiB, t=3, p=1`` takes a few hundred milliseconds,
which is the right order of magnitude for an interactive unlock.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import asdict, dataclass
from typing import Optional

from argon2 import PasswordHasher
from argon2.low_level import Type
from argon2.exceptions import VerifyMismatchError


# --- Password hashing (for the hint answer, which is shorter) --------

# Parameters are tuned for verifying a short answer string, not a
# password. They still cost more than a single SHA, but we don't need
# the full KDF cost because the answer is also gated by file access.

_ANSWER_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19456,  # 19 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def hash_answer(answer: str) -> str:
    """Hash a normalized hint answer with a per-user salt."""
    return _ANSWER_HASHER.hash(answer)


def verify_answer(hash_str: str, answer: str) -> bool:
    try:
        _ANSWER_HASHER.verify(hash_str, answer)
        return True
    except VerifyMismatchError:
        return False


# --- KDF parameters ---------------------------------------------------

@dataclass(frozen=True)
class KDFParams:
    alg: str
    t: int
    m: int  # KiB
    p: int
    salt_b64: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "KDFParams":
        return cls(
            alg=d["alg"],
            t=int(d["t"]),
            m=int(d["m"]),
            p=int(d["p"]),
            salt_b64=str(d["salt_b64"]),
        )


DEFAULT_KDF_PARAMS = {
    "alg": "argon2id",
    "t": 3,
    "m": 65536,  # 64 MiB
    "p": 1,
}


def new_salt() -> str:
    """Return a base64url-encoded 16-byte salt (with padding stripped)."""
    import base64
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


def make_kdf_params() -> KDFParams:
    return KDFParams(
        alg=DEFAULT_KDF_PARAMS["alg"],
        t=DEFAULT_KDF_PARAMS["t"],
        m=DEFAULT_KDF_PARAMS["m"],
        p=DEFAULT_KDF_PARAMS["p"],
        salt_b64=new_salt(),
    )


# --- Key derivation ---------------------------------------------------

def _hasher_from_params(params: KDFParams) -> PasswordHasher:
    if params.alg != "argon2id":
        raise ValueError(f"unsupported KDF: {params.alg}")
    return PasswordHasher(
        time_cost=params.t,
        memory_cost=params.m,
        parallelism=params.p,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )


def derive_key_with_params(password: str, params: KDFParams) -> bytes:
    """Derive a 32-byte key from ``password`` using ``params``."""
    import base64
    pad = "=" * (-len(params.salt_b64) % 4)
    salt = base64.urlsafe_b64decode((params.salt_b64 + pad).encode("ascii"))
    from argon2.low_level import hash_secret_raw
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.t,
        memory_cost=params.m,
        parallelism=params.p,
        hash_len=32,
        type=Type.ID,
    )


def derive_key(password: str, *, salt: Optional[bytes] = None) -> tuple[bytes, KDFParams]:
    """Derive a key with fresh parameters. Returns (key, params)."""
    params = make_kdf_params()
    if salt is not None:
        import base64
        params = KDFParams(
            alg=params.alg, t=params.t, m=params.m, p=params.p,
            salt_b64=base64.urlsafe_b64encode(salt).decode("ascii"),
        )
    return derive_key_with_params(password, params), params
