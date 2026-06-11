"""AES-256-GCM authenticated encryption.

Each call generates a fresh 12-byte nonce. The output is the ciphertext
with the 16-byte GCM tag appended (which is what ``cryptography`` does
by default).
"""

from __future__ import annotations

import os
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aead_encrypt(key: bytes, plaintext: bytes, *, aad: Optional[bytes] = None) -> bytes:
    """Encrypt and authenticate ``plaintext`` with ``key`` (32 bytes)."""
    if len(key) != 32:
        raise ValueError("AEAD key must be 32 bytes")
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ct


def aead_decrypt(key: bytes, blob: bytes, *, aad: Optional[bytes] = None) -> bytes:
    """Decrypt and verify ``blob`` produced by :func:`aead_encrypt`."""
    if len(key) != 32:
        raise ValueError("AEAD key must be 32 bytes")
    if len(blob) < 12 + 16:
        raise ValueError("AEAD blob is too short")
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)
