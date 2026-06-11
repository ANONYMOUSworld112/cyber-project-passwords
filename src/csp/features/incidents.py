"""Incident tracker.

An incident is a record of a security event the user is investigating.
Stored as a list of dicts in the user's encrypted vault.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from csp.auth.vault_store import mutate
from csp.errors import FeatureError, UserError


_SEVERITIES = {"low", "med", "high", "critical"}
_STATUSES = {"open", "closed"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


def _find_index(items: List[dict], iid: str) -> int:
    for i, x in enumerate(items):
        if x.get("id") == iid:
            return i
    return -1


def add_incident(
    title: str,
    severity: str = "med",
    notes: str = "",
    iocs: Optional[List[str]] = None,
) -> dict:
    if not title:
        raise UserError("title must not be empty")
    sev = severity.lower()
    if sev not in _SEVERITIES:
        raise UserError(f"severity must be one of {sorted(_SEVERITIES)}")
    inc = {
        "id": _new_id(),
        "title": title,
        "severity": sev,
        "status": "open",
        "created": _now(),
        "updated": _now(),
        "notes": notes,
        "iocs": list(iocs or []),
    }

    def _m(payload: dict) -> None:
        payload.setdefault("incidents", []).append(inc)

    mutate(_m)
    return inc


def list_incidents(include_closed: bool = True) -> List[dict]:
    from csp.auth.vault_store import load_vault
    items = load_vault().get("incidents", [])
    if include_closed:
        return list(items)
    return [i for i in items if i.get("status") == "open"]


def get_incident(iid: str) -> dict:
    from csp.auth.vault_store import load_vault
    for i in load_vault().get("incidents", []):
        if i.get("id") == iid:
            return i
    raise FeatureError(f"no incident with id {iid}")


def update_incident(
    iid: str,
    *,
    title: Optional[str] = None,
    severity: Optional[str] = None,
    notes: Optional[str] = None,
    iocs: Optional[List[str]] = None,
) -> dict:
    def _m(payload: dict) -> None:
        items = payload.get("incidents", [])
        idx = _find_index(items, iid)
        if idx < 0:
            raise FeatureError(f"no incident with id {iid}")
        inc = items[idx]
        if title is not None:
            inc["title"] = title
        if severity is not None:
            sev = severity.lower()
            if sev not in _SEVERITIES:
                raise UserError(f"severity must be one of {sorted(_SEVERITIES)}")
            inc["severity"] = sev
        if notes is not None:
            inc["notes"] = notes
        if iocs is not None:
            inc["iocs"] = list(iocs)
        inc["updated"] = _now()

    mutate(_m)
    return get_incident(iid)


def close_incident(iid: str) -> dict:
    def _m(payload: dict) -> None:
        items = payload.get("incidents", [])
        idx = _find_index(items, iid)
        if idx < 0:
            raise FeatureError(f"no incident with id {iid}")
        inc = items[idx]
        inc["status"] = "closed"
        inc["updated"] = _now()

    mutate(_m)
    return get_incident(iid)
