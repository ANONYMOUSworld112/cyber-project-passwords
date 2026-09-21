"""Local hash database for file lookups.

Imports a list of SHA-256 hashes from a plain-text file (one per line,
optional comma-separated label) and stores them in the user's vault.
Lookups return malicious / clean / unknown.

The import is purely local: the file is read, hashes are added, and the
file path is recorded in ``sources.json`` (which contains no secrets).
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from csp.auth.vault_store import mutate
from csp.errors import FeatureError, UserError
from csp.io_utils.atomic_write import atomic_write_text
from csp.paths import hashdb_sources_file


_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _load_sources() -> list:
    p = hashdb_sources_file()
    if not p.exists():
        return []
    import json
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, ValueError):
        return []


def _save_sources(sources: list) -> None:
    import json
    from csp.io_utils.fs_perms import private_file
    atomic_write_text(
        hashdb_sources_file(),
        json.dumps(sources, indent=2, sort_keys=True),
    )
    private_file(hashdb_sources_file())


def hashdb_import(file_path: str, label_kind: str = "malicious") -> dict:
    if label_kind not in ("malicious", "clean"):
        raise UserError("label_kind must be 'malicious' or 'clean'")
    p = Path(file_path).expanduser()
    if not p.is_file():
        raise UserError(f"file not found: {file_path}")
    text = p.read_text(encoding="utf-8", errors="replace")
    added = 0
    skipped = 0
    new_entries: Dict[str, dict] = {}
    now_ts = _now()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(",", 1)
        h = parts[0].strip()
        label = parts[1].strip() if len(parts) > 1 else ""
        if not _SHA256_RE.match(h):
            skipped += 1
            continue
        h = h.lower()
        new_entries[h] = {"label": label, "source": p.name, "imported": now_ts}
        added += 1

    if new_entries:
        def _m(payload: dict) -> None:
            hdb = payload.setdefault("hashdb", {"known_malicious": {}, "known_clean": {}})
            hdb.setdefault("known_malicious", {})
            hdb.setdefault("known_clean", {})
            target = hdb["known_malicious"] if label_kind == "malicious" else hdb["known_clean"]
            target.update(new_entries)
        mutate(_m)

    sources = _load_sources()
    sources.append({
        "path": str(p),
        "label_kind": label_kind,
        "added": added,
        "skipped": skipped,
        "imported_at": now_ts,
    })
    _save_sources(sources)
    return {"added": added, "skipped": skipped, "source": str(p)}


def hashdb_lookup(sha256: str) -> dict:
    from csp.auth.vault_store import load_vault
    if not _SHA256_RE.match(sha256):
        raise UserError("not a valid SHA-256 hash")
    sha = sha256.lower()
    hdb = load_vault().get("hashdb", {})
    mal = hdb.get("known_malicious", {})
    clean = hdb.get("known_clean", {})
    if sha in mal:
        return {"status": "malicious", "label": mal[sha].get("label", ""), "source": mal[sha].get("source", "")}
    if sha in clean:
        return {"status": "clean", "label": clean[sha].get("label", ""), "source": clean[sha].get("source", "")}
    return {"status": "unknown"}


def hashdb_list_sources() -> list:
    return _load_sources()


def hash_file(path: str) -> str:
    """Helper: compute SHA-256 of a file (used by REPL convenience)."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise UserError(f"file not found: {path}")
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
