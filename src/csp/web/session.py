from __future__ import annotations

import secrets
import threading
import time
from typing import Optional

from csp.auth.session import Session

_sessions: dict[str, Session] = {}
_timestamps: dict[str, float] = {}
_lock = threading.Lock()
_TIMEOUT = 15 * 60


def create_session(s: Session) -> str:
    token = secrets.token_hex(32)
    with _lock:
        _sessions[token] = s
        _timestamps[token] = time.time()
    return token


def get_session(token: str) -> Optional[Session]:
    with _lock:
        ts = _timestamps.get(token)
        if ts is None:
            return None
        if time.time() - ts > _TIMEOUT:
            sess = _sessions.pop(token, None)
            _timestamps.pop(token, None)
            if sess is not None:
                sess.wipe()
            return None
        _timestamps[token] = time.time()
        return _sessions.get(token)


def destroy_session(token: str) -> None:
    with _lock:
        sess = _sessions.pop(token, None)
        _timestamps.pop(token, None)
        if sess is not None:
            sess.wipe()


def wipe_all() -> None:
    with _lock:
        for sess in _sessions.values():
            sess.wipe()
        _sessions.clear()
        _timestamps.clear()


def cleanup_expired() -> int:
    now = time.time()
    with _lock:
        expired = [t for t, ts in _timestamps.items() if now - ts > _TIMEOUT]
        for t in expired:
            sess = _sessions.pop(t, None)
            _timestamps.pop(t, None)
            if sess is not None:
                sess.wipe()
        return len(expired)
