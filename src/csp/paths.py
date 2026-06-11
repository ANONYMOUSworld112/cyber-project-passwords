"""Cross-platform data directory resolution.

The data directory is intentionally separate from any user-controlled
location and is never synced, shared, or transmitted. All file paths the
application ever touches are derived from the helpers in this module.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from platformdirs import user_data_dir

_APP_NAME = "cyber-project-passwords"
_APP_AUTHOR = "csp"


def data_dir() -> Path:
    """Return the root data directory, creating it if needed.

    Honors the ``CSP_DATA_DIR`` environment variable for tests and
    portable installs. Otherwise uses the OS-appropriate user data dir.
    """
    override = os.environ.get("CSP_DATA_DIR")
    if override:
        p = Path(override)
    else:
        p = Path(user_data_dir(_APP_NAME, _APP_AUTHOR, roaming=False))
    p.mkdir(parents=True, exist_ok=True)
    return p


def master_file() -> Path:
    return data_dir() / "master.json"


def lock_file() -> Path:
    return data_dir() / "lock.json"


def lockout_file() -> Path:
    return data_dir() / "lockout.json"


def user_dir(name: str) -> Path:
    return data_dir() / "users" / name


def profile_pw_file(name: str) -> Path:
    return user_dir(name) / "profile_pw.enc"


def hint_pub_file(name: str) -> Path:
    return user_dir(name) / "hint_pub.enc"


def vault_file(name: str) -> Path:
    return user_dir(name) / "vault.enc"


def hashdb_dir() -> Path:
    p = data_dir() / "hashdb"
    p.mkdir(parents=True, exist_ok=True)
    return p


def hashdb_sources_file() -> Path:
    return hashdb_dir() / "sources.json"


def data_dir_override(p: Optional[Path]) -> None:
    """Test helper: force data_dir() to return a specific path."""
    if p is None:
        os.environ.pop("CSP_DATA_DIR", None)
    else:
        os.environ["CSP_DATA_DIR"] = str(p)
