"""Filesystem permission helpers.

The application stores credentials, encrypted vaults, lock files, and
lockout state. On POSIX we tighten permissions so only the owning user
can read or write them. On Windows the ACL model is different; the best
practical mitigation is to keep the data directory inside the user's
profile, which platformdirs already does.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


def private_file(path: Path) -> None:
    """Set ``path`` to owner read/write only (0600 on POSIX)."""
    path = Path(path)
    if not path.exists():
        return
    if os.name == "posix":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            # Permission changes can fail in some sandboxes; not fatal.
            pass


def private_dir(path: Path) -> None:
    """Set ``path`` to owner read/write/execute (0700 on POSIX)."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except OSError:
            pass
