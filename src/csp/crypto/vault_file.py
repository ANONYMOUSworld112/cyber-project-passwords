"""Encrypted vault file format.

Every encrypted blob on disk is wrapped in a small JSON envelope. The
envelope carries the KDF parameters and nonce *outside* the ciphertext,
so a reader can load the file and prepare to derive a key before
attempting decryption.

On-disk shape (one JSON object, pretty-printed for human inspection):

::

    {
      "v": 1,
      "kdf": {
        "alg": "argon2id",
        "t": 3,
        "m": 65536,
        "p": 1,
        "salt_b64": "..."
      },
      "nonce": "<unused: nonce is inside ct prefix>",
      "ct": "<base64 of nonce || ciphertext || tag>"
    }

The ``nonce`` field is kept for forward compatibility (e.g., moving
the nonce out of the ciphertext prefix) but the current implementation
prepends the nonce to ``ct`` to keep the file self-describing.

AAD is set to the JSON serialization of ``{"v": 1, "kdf": ...}`` so
that any tampering with KDF parameters or version invalidates the
authentication tag.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.exceptions import InvalidTag

from csp.crypto.aead import aead_decrypt, aead_encrypt
from csp.crypto.kdf import KDFParams
from csp.errors import CorruptVaultError, VaultError


_FILE_VERSION = 1


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


@dataclass
class VaultFile:
    kdf: KDFParams
    blob: bytes  # nonce || ciphertext || tag

    def to_json(self) -> str:
        env = {
            "v": _FILE_VERSION,
            "kdf": self.kdf.to_dict(),
            "nonce": "",  # reserved; nonce is the first 12 bytes of blob
            "ct": _b64e(self.blob),
        }
        return json.dumps(env, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "VaultFile":
        try:
            env = json.loads(text)
        except json.JSONDecodeError as e:
            raise CorruptVaultError(f"invalid JSON: {e}") from e
        if not isinstance(env, dict):
            raise CorruptVaultError("envelope must be a JSON object")
        v = int(env.get("v", 0))
        if v != _FILE_VERSION:
            raise CorruptVaultError(f"unsupported envelope version: {v}")
        try:
            kdf = KDFParams.from_dict(env["kdf"])
            blob = _b64d(env["ct"])
        except (KeyError, ValueError) as e:
            raise CorruptVaultError(f"missing/invalid field: {e}") from e
        return cls(kdf=kdf, blob=blob)


def _aad(env_no_ct: dict) -> bytes:
    return json.dumps(env_no_ct, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_vault_file(target_path, payload: Any, kdf: KDFParams, key: bytes) -> None:
    """Encrypt ``payload`` (JSON-serializable) and write atomically."""
    from csp.io_utils.atomic_write import atomic_write_text
    from csp.io_utils.fs_perms import private_file
    plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
    blob = aead_encrypt(key, plaintext)
    vf = VaultFile(kdf=kdf, blob=blob)
    env_no_ct = {"v": _FILE_VERSION, "kdf": kdf.to_dict(), "nonce": ""}
    # We must encrypt with AAD tied to the envelope, so we re-derive
    # blob with AAD set. The first 12 bytes of ``blob`` are the nonce.
    nonce = blob[:12]
    ct_with_tag = blob[12:]
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aad = _aad(env_no_ct)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    final_blob = nonce + ct_tag
    vf2 = VaultFile(kdf=kdf, blob=final_blob)
    atomic_write_text(target_path, vf2.to_json())
    private_file(target_path)


def read_vault_file(target_path, key: bytes) -> Any:
    """Read, decrypt, and JSON-parse an encrypted vault file."""
    text = target_path.read_text(encoding="utf-8")
    vf = VaultFile.from_json(text)
    env_no_ct = {"v": _FILE_VERSION, "kdf": vf.kdf.to_dict(), "nonce": ""}
    aad = _aad(env_no_ct)
    nonce = vf.blob[:12]
    ct_with_tag = vf.blob[12:]
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct_with_tag, aad)
    except InvalidTag as e:
        raise CorruptVaultError("authentication failed (wrong key or tampered file)") from e
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise CorruptVaultError(f"invalid decrypted payload: {e}") from e


def make_vault_envelope(kdf: KDFParams, payload: Any, key: bytes) -> VaultFile:
    """Build a VaultFile in memory (used by tests and atomic writer)."""
    plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
    env_no_ct = {"v": _FILE_VERSION, "kdf": kdf.to_dict(), "nonce": ""}
    aad = _aad(env_no_ct)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = __import__("secrets").token_bytes(12)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return VaultFile(kdf=kdf, blob=nonce + ct_tag)
