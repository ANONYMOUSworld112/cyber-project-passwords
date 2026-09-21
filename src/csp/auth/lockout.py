"""Per-user failed-attempt tracking and progressive lockout.

A user is locked out after repeated authentication failures. The
thresholds are deliberately steep; on a personal machine a few wrong
keystrokes should not lock the user out, but a brute-force attack
across millions of guesses is the threat we're defending against.

Lockouts expire automatically. We persist the ``lock_until`` timestamp
so a process restart does not bypass the lock.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Optional

from csp.errors import LockedOutError
from csp.io_utils.atomic_write import atomic_write_text
from csp.io_utils.fs_perms import private_file
from csp.paths import lockout_file


# Thresholds: (fail_count_to_trigger, lockout_seconds)
_LOCKOUT_TIERS = [
    (5, 5 * 60),         # 5 min after 5 fails
    (10, 30 * 60),       # 30 min after 10 fails
    (20, 24 * 60 * 60),  # 24 h after 20 fails
]


def _next_lock_seconds(fail_count: int) -> int:
    secs = 0
    for trigger, lock_secs in _LOCKOUT_TIERS:
        if fail_count >= trigger:
            secs = lock_secs
    return secs


@dataclass
class LockoutState:
    fails: int
    lock_until: Optional[float]  # unix timestamp; None means not locked

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "LockoutState":
        lu = d.get("lock_until")
        return cls(fails=int(d.get("fails", 0)), lock_until=float(lu) if lu else None)


def _load_all() -> Dict[str, dict]:
    path = lockout_file()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        return {}


def _save_all(data: Dict[str, dict]) -> None:
    atomic_write_text(lockout_file(), json.dumps(data, indent=2, sort_keys=True))
    private_file(lockout_file())


def get_lockout_state(username: str) -> LockoutState:
    data = _load_all()
    rec = data.get(username)
    if not rec:
        return LockoutState(fails=0, lock_until=None)
    st = LockoutState.from_dict(rec)
    # If the lock has expired, reset the fail counter.
    if st.lock_until is not None and st.lock_until <= time.time():
        st = LockoutState(fails=0, lock_until=None)
        data[username] = st.to_dict()
        _save_all(data)
    return st


def _set_state(username: str, st: LockoutState) -> None:
    data = _load_all()
    data[username] = st.to_dict()
    _save_all(data)


def check_lock(username: str) -> None:
    """Raise :class:`LockedOutError` if the user is currently locked out."""
    st = get_lockout_state(username)
    if st.lock_until is not None and st.lock_until > time.time():
        remaining = int(st.lock_until - time.time())
        raise LockedOutError(
            f"Account '{username}' is locked. Try again in {remaining} seconds."
        )


def register_failure(username: str) -> LockoutState:
    st = get_lockout_state(username)
    st.fails += 1
    lock_secs = _next_lock_seconds(st.fails)
    st.lock_until = time.time() + lock_secs if lock_secs else None
    _set_state(username, st)
    return st


def register_success(username: str) -> None:
    data = _load_all()
    if username in data:
        del data[username]
        _save_all(data)


def clear_lockout(username: str) -> None:
    register_success(username)
