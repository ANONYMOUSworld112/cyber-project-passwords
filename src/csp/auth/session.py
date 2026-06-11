"""In-memory session state.

A :class:`Session` holds the password-derived key for the currently
logged-in user. The key is wrapped in a :class:`SecretBuffer` so it can
be wiped. The session is a process-wide singleton accessed via
:func:`current_session`.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Iterator, Optional

from csp.crypto.kdf import KDFParams
from csp.crypto.memzero import SecretBuffer, wipe


@dataclass
class Session:
    user: str
    key: SecretBuffer
    kdf: KDFParams
    # The decrypted vault payload is cached in memory while the session
    # is alive. It is wiped on lock/exit. Mutations call
    # ``vault_store.save_vault`` which deep-copies into this attribute.
    _vault_cache: Optional[dict] = None

    def wipe(self) -> None:
        self.key.wipe()
        if self._vault_cache is not None:
            self._vault_cache.clear()
            self._vault_cache = None

    def get_key(self) -> bytes:
        return self.key.get()


_lock = threading.Lock()
_session: Optional[Session] = None


def current_session() -> Optional[Session]:
    return _session


def set_session(s: Optional[Session]) -> None:
    global _session
    with _lock:
        if _session is not None and s is not _session:
            _session.wipe()
        _session = s


def require_session() -> Session:
    s = current_session()
    if s is None:
        raise RuntimeError("no active session; this is a bug")
    return s


@contextmanager
def temporary_session(s: Session) -> Iterator[Session]:
    """Context manager that installs a session and wipes it on exit."""
    set_session(s)
    try:
        yield s
    finally:
        if s.key is not None:
            s.wipe()
        set_session(None)
