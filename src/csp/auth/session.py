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
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Dict, Iterator, Optional

from csp.crypto.kdf import KDFParams
from csp.crypto.memzero import SecretBuffer, wipe


@dataclass
class Session:
    user: str
    key: SecretBuffer
    kdf: KDFParams
    _vault_cache: Optional[dict] = None

    def wipe(self) -> None:
        self.key.wipe()
        if self._vault_cache is not None:
            self._vault_cache.clear()
            self._vault_cache = None

    def get_key(self) -> bytes:
        return self.key.get()


_lock = threading.Lock()
_global_session: Optional[Session] = None
_ctx_session: ContextVar[Optional[Session]] = ContextVar("_ctx_session", default=None)


def current_session() -> Optional[Session]:
    s = _ctx_session.get()
    if s is not None:
        return s
    return _global_session


def set_session(s: Optional[Session]) -> None:
    global _global_session
    with _lock:
        _global_session = s


@contextmanager
def bind_session(s: Optional[Session]) -> Iterator[Optional[Session]]:
    token = _ctx_session.set(s)
    try:
        yield s
    finally:
        _ctx_session.reset(token)


def require_session() -> Session:
    s = current_session()
    if s is None:
        raise RuntimeError("no active session; this is a bug")
    return s


@contextmanager
def temporary_session(s: Session) -> Iterator[Session]:
    token = _ctx_session.set(s)
    set_session(s)
    try:
        yield s
    finally:
        if s.key is not None:
            s.wipe()
        _ctx_session.reset(token)
        set_session(None)
