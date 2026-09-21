"""Credential vault feature.

Stores credentials as a list of dicts in the user's encrypted vault.
Each credential has:

- id: short random identifier (16 hex chars)
- title: human label
- username: account username
- password: account password (stored verbatim; encryption is at the
  vault level)
- url: optional URL
- notes: free-form notes
- created: ISO timestamp
- updated: ISO timestamp
"""

from __future__ import annotations

import secrets
import string
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from csp.auth.vault_store import mutate
from csp.errors import FeatureError, UserError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


def _find_index(items: List[dict], cred_id: str) -> int:
    for i, c in enumerate(items):
        if c.get("id") == cred_id:
            return i
    return -1


def add_credential(
    title: str,
    username: str,
    password: str,
    url: str = "",
    notes: str = "",
) -> dict:
    if not title:
        raise UserError("title must not be empty")
    if not username:
        raise UserError("username must not be empty")
    if not password:
        raise UserError("password must not be empty")
    cred = {
        "id": _new_id(),
        "title": title,
        "username": username,
        "password": password,
        "url": url,
        "notes": notes,
        "created": _now(),
        "updated": _now(),
    }

    def _m(payload: dict) -> None:
        payload.setdefault("credentials", []).append(cred)

    mutate(_m)
    return cred


def list_credentials() -> List[dict]:
    from csp.auth.vault_store import load_vault
    return list(load_vault().get("credentials", []))


def get_credential(cred_id: str) -> dict:
    from csp.auth.vault_store import load_vault
    for c in load_vault().get("credentials", []):
        if c.get("id") == cred_id:
            return c
    raise FeatureError(f"no credential with id {cred_id}")


def update_credential(
    cred_id: str,
    *,
    title: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    url: Optional[str] = None,
    notes: Optional[str] = None,
) -> dict:
    def _m(payload: dict) -> None:
        items = payload.get("credentials", [])
        idx = _find_index(items, cred_id)
        if idx < 0:
            raise FeatureError(f"no credential with id {cred_id}")
        c = items[idx]
        if title is not None:
            c["title"] = title
        if username is not None:
            c["username"] = username
        if password is not None:
            c["password"] = password
        if url is not None:
            c["url"] = url
        if notes is not None:
            c["notes"] = notes
        c["updated"] = _now()

    mutate(_m)
    return get_credential(cred_id)


def delete_credential(cred_id: str) -> None:
    def _m(payload: dict) -> None:
        items = payload.get("credentials", [])
        idx = _find_index(items, cred_id)
        if idx < 0:
            raise FeatureError(f"no credential with id {cred_id}")
        del items[idx]

    mutate(_m)


def search_credentials(query: str) -> List[dict]:
    q = query.lower()
    out = []
    for c in list_credentials():
        hay = " ".join(
            str(c.get(k, "")) for k in ("title", "username", "url", "notes")
        ).lower()
        if q in hay:
            out.append(c)
    return out


def generate_password(length: int = 20) -> str:
    if length < 8:
        raise UserError("length must be at least 8")
    if length > 256:
        raise UserError("length must be at most 256")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>/?"
    return "".join(secrets.choice(alphabet) for _ in range(length))
