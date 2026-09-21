"""Log analyzer.

A simple, fully-offline log parser. Detects syslog, auth.log, and
generic "key=value" or "level: message" lines. Produces a summary with
top error patterns and the first 20 lines, and stores it as a "run" in
the user's vault.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from csp.auth.vault_store import mutate
from csp.errors import UserError


_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.*)$"
)
_KV_RE = re.compile(r"(\w+)\s*=\s*(\S+)")
_LEVEL_RE = re.compile(r"\b(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b", re.IGNORECASE)
_AUTH_FAIL_RE = re.compile(r"(?i)failed password|authentication failure|invalid user")
_AUTH_OK_RE = re.compile(r"(?i)accepted password|session opened|accepted publickey")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


def _classify(line: str) -> str:
    m = _LEVEL_RE.search(line)
    if m:
        return m.group("level").upper()
    if _AUTH_FAIL_RE.search(line):
        return "AUTH_FAIL"
    if _AUTH_OK_RE.search(line):
        return "AUTH_OK"
    return "INFO"


def _detect_format(sample: str) -> str:
    if _SYSLOG_RE.search(sample):
        return "syslog"
    if _KV_RE.search(sample):
        return "kv"
    if _LEVEL_RE.search(sample):
        return "leveled"
    return "plain"


def logs_analyze(file_path: str, max_top: int = 10, sample_lines: int = 20) -> dict:
    p = Path(file_path).expanduser()
    if not p.is_file():
        raise UserError(f"file not found: {file_path}")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        raise UserError("file is empty")

    fmt = _detect_format("\n".join(lines[:50]))
    levels = Counter()
    patterns = Counter()
    by_message: Counter = Counter()
    error_lines: List[str] = []
    sample: List[str] = []

    for i, line in enumerate(lines):
        if i < sample_lines:
            sample.append(line)
        lvl = _classify(line)
        levels[lvl] += 1
        if lvl in ("ERROR", "FATAL", "CRITICAL", "AUTH_FAIL"):
            error_lines.append(line)
        # Build a coarse pattern by stripping numbers/hex/uuid/timestamps.
        pat = re.sub(r"\b[0-9a-f]{8,}\b", "<hex>", line, flags=re.IGNORECASE)
        pat = re.sub(r"\b\d+\b", "<n>", pat)
        pat = re.sub(r"\d{2}:\d{2}:\d{2}", "<t>", pat)
        by_message[pat] += 1
    patterns = Counter(dict(by_message.most_common(max_top)))

    summary = {
        "id": _new_id(),
        "path": str(p),
        "format": fmt,
        "lines": len(lines),
        "levels": dict(levels),
        "top_patterns": [
            {"pattern": k, "count": v} for k, v in patterns.items()
        ],
        "sample_lines": sample,
        "error_lines": error_lines[:20],
        "analyzed_at": _now(),
    }

    def _m(payload: dict, _summary=summary) -> None:
        payload.setdefault("logs_runs", []).append(_summary)
        # Cap stored runs to a reasonable size.
        if len(payload["logs_runs"]) > 200:
            payload["logs_runs"] = payload["logs_runs"][-200:]

    mutate(_m)
    return summary


def list_log_runs(limit: int = 50) -> List[dict]:
    from csp.auth.vault_store import load_vault
    items = load_vault().get("logs_runs", [])
    return list(items[-limit:][::-1])
