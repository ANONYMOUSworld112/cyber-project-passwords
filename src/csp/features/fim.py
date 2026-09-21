"""File integrity monitor.

Hashes a directory tree, stores the baseline (relative paths -> SHA-256,
size, mtime) in the user's encrypted vault, and on ``fim_scan`` reports
files that are added, removed, or changed since the baseline.

Constraints:
- Does not follow symlinks.
- Skips special files (devices, sockets, FIFOs).
- Stops on permission errors per file and records them in the report.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from csp.auth.vault_store import mutate
from csp.errors import FeatureError, UserError


_HASH_CHUNK = 1 << 20  # 1 MiB


def _hash_file(path: Path) -> Optional[Dict[str, object]]:
    try:
        st = path.stat()
    except OSError:
        return None
    if not path.is_file() or path.is_symlink():
        return None
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(_HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as e:
        return {"error": str(e), "path": str(path)}
    return {
        "sha256": h.hexdigest(),
        "size": st.st_size,
        "mtime": st.st_mtime,
    }


def _walk_files(root: Path) -> List[Path]:
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Filter out symlinked dirs in-place to prevent descent.
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink():
                continue
            out.append(p)
    return out


def _snapshot(root: Path) -> Tuple[Dict[str, dict], List[dict]]:
    """Build a {relpath: record} snapshot under ``root``."""
    snap: Dict[str, dict] = {}
    errors: List[dict] = []
    for p in _walk_files(root):
        rec = _hash_file(p)
        if rec is None:
            continue
        if "error" in rec:
            errors.append({"path": rec["path"], "error": rec["error"]})
            continue
        rel = str(p.relative_to(root))
        snap[rel] = rec  # type: ignore[assignment]
    return snap, errors


def _watched_paths() -> List[str]:
    from csp.auth.vault_store import load_vault
    fim = load_vault().get("fim", {})
    return list(fim.get("watched_paths", []))


def _normalize_root(root: str) -> str:
    p = Path(root).expanduser().resolve()
    if not p.exists():
        raise UserError(f"path does not exist: {root}")
    if not p.is_dir():
        raise UserError(f"not a directory: {root}")
    return str(p)


def fim_baseline(root: str) -> dict:
    """Hash the tree under ``root`` and store the snapshot."""
    root_abs = _normalize_root(root)
    snap, errors = _snapshot(Path(root_abs))

    def _m(payload: dict) -> None:
        fim = payload.setdefault("fim", {"baseline": {}, "watched_paths": []})
        fim.setdefault("baseline", {})
        fim.setdefault("watched_paths", [])
        fim["baseline"][root_abs] = snap
        if root_abs not in fim["watched_paths"]:
            fim["watched_paths"].append(root_abs)

    mutate(_m)
    return {
        "root": root_abs,
        "files": len(snap),
        "errors": errors,
    }


def fim_scan(root: Optional[str] = None) -> dict:
    """Compare current snapshot against the stored baseline."""
    from csp.auth.vault_store import load_vault
    fim = load_vault().get("fim", {})
    baselines: Dict[str, dict] = fim.get("baseline", {})
    if not baselines:
        raise FeatureError("no baselines stored; run 'fim baseline <path>' first")
    if root is not None:
        root_abs = _normalize_root(root)
        if root_abs not in baselines:
            raise FeatureError(f"no baseline for {root_abs}")
        targets = {root_abs: baselines[root_abs]}
    else:
        targets = dict(baselines)

    report = {"scans": [], "total_changes": 0}
    for r, baseline in targets.items():
        current, errors = _snapshot(Path(r))
        added = sorted(set(current) - set(baseline))
        removed = sorted(set(baseline) - set(current))
        common = set(current) & set(baseline)
        changed = sorted(
            p for p in common
            if current[p]["sha256"] != baseline[p]["sha256"]
            or current[p]["size"] != baseline[p]["size"]
        )
        scan = {
            "root": r,
            "added": added,
            "removed": removed,
            "changed": changed,
            "errors": errors,
        }
        scan["total"] = len(added) + len(removed) + len(changed)
        report["scans"].append(scan)
        report["total_changes"] += scan["total"]
    return report


def fim_watch_add(root: str) -> None:
    root_abs = _normalize_root(root)
    # Ensure there's a baseline so the watch is meaningful.
    if not Path(root_abs).exists():
        raise UserError(f"path does not exist: {root}")
    def _m(payload: dict) -> None:
        fim = payload.setdefault("fim", {"baseline": {}, "watched_paths": []})
        fim.setdefault("watched_paths", [])
        if root_abs not in fim["watched_paths"]:
            fim["watched_paths"].append(root_abs)
        fim.setdefault("baseline", {}).setdefault(root_abs, {})
    mutate(_m)


def fim_watch_remove(root: str) -> None:
    root_abs = str(Path(root).expanduser().resolve())
    def _m(payload: dict) -> None:
        fim = payload.setdefault("fim", {"baseline": {}, "watched_paths": []})
        fim["watched_paths"] = [p for p in fim.get("watched_paths", []) if p != root_abs]
        fim.get("baseline", {}).pop(root_abs, None)
    mutate(_m)


def fim_watch_list() -> List[str]:
    return _watched_paths()
