"""crypto tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from csp.crypto.aead import aead_decrypt, aead_encrypt
from csp.crypto.kdf import (
    DEFAULT_KDF_PARAMS,
    KDFParams,
    derive_key_with_params,
    hash_answer,
    make_kdf_params,
    verify_answer,
)
from csp.crypto.memzero import SecretBuffer, wipe
from csp.crypto.vault_file import (
    VaultFile,
    read_vault_file,
    write_vault_file,
)


def test_aead_roundtrip():
    key = b"\x00" * 32
    pt = b"hello world"
    blob = aead_encrypt(key, pt)
    assert aead_decrypt(key, blob) == pt


def test_aead_tamper_detected():
    key = b"\x01" * 32
    blob = aead_encrypt(key, b"secret")
    tampered = bytearray(blob)
    tampered[-1] ^= 1
    with pytest.raises(Exception):
        aead_decrypt(key, bytes(tampered))


def test_aead_wrong_key():
    blob = aead_encrypt(b"\x02" * 32, b"x")
    with pytest.raises(Exception):
        aead_decrypt(b"\x03" * 32, blob)


def test_aead_aad_mismatch():
    key = b"\x04" * 32
    blob = aead_encrypt(key, b"x", aad=b"context")
    with pytest.raises(Exception):
        aead_decrypt(key, blob, aad=b"other")


def test_kdf_deterministic_with_same_params():
    import base64
    salt_bytes = b"\x00" * 16
    salt_b64 = base64.urlsafe_b64encode(salt_bytes).decode("ascii").rstrip("=")
    params = KDFParams(alg="argon2id", t=1, m=8192, p=1, salt_b64=salt_b64)
    k1 = derive_key_with_params("hunter22pass", params)
    k2 = derive_key_with_params("hunter22pass", params)
    assert k1 == k2
    assert len(k1) == 32


def test_kdf_different_passwords_differ():
    params = make_kdf_params()
    a = derive_key_with_params("password123A", params)
    b = derive_key_with_params("password123B", params)
    assert a != b


def test_hash_answer_verifies():
    h = hash_answer("my dog has fleas")
    assert verify_answer(h, "my dog has fleas")
    assert not verify_answer(h, "wrong answer")


def test_vault_file_roundtrip(tmp_path: Path):
    kdf = make_kdf_params()
    key = derive_key_with_params("supersecretpw1", kdf)
    target = tmp_path / "test.enc"
    payload = {"a": 1, "b": [1, 2, 3], "c": "hello"}
    write_vault_file(target, payload, kdf, key)
    out = read_vault_file(target, key)
    assert out == payload


def test_vault_file_wrong_key(tmp_path: Path):
    kdf = make_kdf_params()
    key1 = derive_key_with_params("supersecretpw1", kdf)
    key2 = derive_key_with_params("differentpw00", kdf)
    target = tmp_path / "test.enc"
    write_vault_file(target, {"x": 1}, kdf, key1)
    with pytest.raises(Exception):
        read_vault_file(target, key2)


def test_vault_file_envelope_has_kdf_outside_ciphertext(tmp_path: Path):
    kdf = make_kdf_params()
    key = derive_key_with_params("supersecretpw1", kdf)
    target = tmp_path / "test.enc"
    write_vault_file(target, {"x": 1}, kdf, key)
    text = target.read_text(encoding="utf-8")
    env = json.loads(text)
    assert env["kdf"]["alg"] == "argon2id"
    assert "ct" in env
    assert "v" in env


def test_secret_buffer_wipe():
    b = SecretBuffer(b"hunter2hunter2")
    assert b.get() == b"hunter2hunter2"
    b.wipe()
    assert b.get() != b"hunter2hunter2"


def test_wipe_bytearray():
    ba = bytearray(b"abc")
    wipe(ba)
    assert ba == bytearray(3)
