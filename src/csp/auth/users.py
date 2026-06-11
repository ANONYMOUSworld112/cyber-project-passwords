"""Master file management.

``master.json`` is the only non-encrypted file in the data directory
that mentions user accounts. It contains no secrets.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from csp.errors import AlreadyInitializedError, NotInitializedError
from csp.io_utils.atomic_write import atomic_write_text
from csp.io_utils.fs_perms import private_file
from csp.paths import master_file

_FILE_VERSION = 1


@dataclass
class Master:
    version: int
    first_run: bool
    users: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Master":
        return cls(
            version=int(d.get("version", _FILE_VERSION)),
            first_run=bool(d.get("first_run", True)),
            users=list(d.get("users", [])),
        )


def load_master() -> Master:
    path = master_file()
    if not path.exists():
        return Master(version=_FILE_VERSION, first_run=True, users=[])
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Master.from_dict(data)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise NotInitializedError(f"master.json is corrupt: {e}") from e


def save_master(m: Master) -> None:
    atomic_write_text(master_file(), json.dumps(m.to_dict(), indent=2, sort_keys=True))
    private_file(master_file())


def first_run() -> bool:
    """Return True if the application has not been set up yet."""
    path = master_file()
    if not path.exists():
        return True
    m = load_master()
    return m.first_run or not m.users


def require_initialized() -> Master:
    if first_run():
        raise NotInitializedError(
            "Application is not initialized. Run 'csp setup' first."
        )
    return load_master()


def require_not_initialized() -> None:
    m = load_master()
    if m.users:
        raise AlreadyInitializedError(
            "Application is already initialized. Use 'csp user add' to add more users."
        )


def list_users() -> List[str]:
    return list(load_master().users)


def user_exists(name: str) -> bool:
    return name in load_master().users


def add_user_to_master(name: str) -> None:
    m = load_master()
    if name in m.users:
        return
    m.users.append(name)
    m.first_run = False
    save_master(m)


def remove_user_from_master(name: str) -> None:
    m = load_master()
    if name not in m.users:
        return
    m.users.remove(name)
    if not m.users:
        m.first_run = True
    save_master(m)


def create_user_dirs(name: str) -> None:
    """Create the per-user directory and tighten its permissions."""
    from csp.paths import user_dir
    from csp.io_utils.fs_perms import private_dir
    d = user_dir(name)
    private_dir(d)


def remove_user(name: str) -> None:
    """Delete a user's directory and remove from master."""
    import shutil
    from csp.paths import user_dir
    d = user_dir(name)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    remove_user_from_master(name)
    # Also drop their lockout state.
    from csp.auth.lockout import clear_lockout
    clear_lockout(name)
