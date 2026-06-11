"""Vault persistence helpers.

These functions mutate the unlocked user's in-memory vault payload and
write it back to disk atomically. They are the only path that touches
the on-disk vault.enc.
"""

from __future__ import annotations

import copy
from typing import Any, Callable

from csp.auth.session import current_session
from csp.crypto.vault_file import write_vault_file
from csp.errors import UserError
from csp.paths import vault_file


def load_vault() -> dict:
    """Return a deep copy of the current session's vault payload."""
    sess = current_session()
    if sess is None:
        raise UserError("no active session")
    if sess._vault_cache is None:
        raise UserError("session has no vault cache")
    return copy.deepcopy(sess._vault_cache)


def save_vault(payload: dict) -> None:
    """Persist the payload to disk and update the session cache."""
    sess = current_session()
    if sess is None:
        raise UserError("no active session")
    write_vault_file(
        vault_file(sess.user),
        payload,
        sess.kdf,
        sess.get_key(),
    )
    sess._vault_cache = copy.deepcopy(payload)


def mutate(mutator: Callable[[dict], None]) -> dict:
    """Load the vault, apply ``mutator`` to it, save it, return it."""
    payload = load_vault()
    mutator(payload)
    save_vault(payload)
    return payload
