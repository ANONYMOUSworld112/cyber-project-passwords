"""Username and password validation rules."""

from __future__ import annotations

import re
import unicodedata
from typing import Optional


_USERNAME_RE = re.compile(r"^[a-z0-9_-]{3,32}$")


def validate_username(name: str) -> Optional[str]:
    """Return None if valid, otherwise an error message."""
    if not name:
        return "username must not be empty"
    if not _USERNAME_RE.match(name):
        return "username must be 3-32 chars of [a-z0-9_-]"
    return None


def validate_password(password: str, username: str = "") -> Optional[str]:
    """Return None if the password meets the policy.

    Policy: length >= 12, at least 3 of {lower, upper, digit, symbol},
    must not equal or contain the username.
    """
    if not password:
        return "password must not be empty"
    if len(password) < 12:
        return "password must be at least 12 characters"
    if len(password) > 1024:
        return "password is unreasonably long"
    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1
    if classes < 3:
        return "password must include at least 3 of: lower, upper, digit, symbol"
    if username:
        uname_lc = username.lower()
        if password.lower() == uname_lc or uname_lc in password.lower():
            return "password must not contain the username"
    return None


def normalize_answer(answer: str) -> str:
    """Normalize a hint answer for stable hashing and comparison."""
    a = unicodedata.normalize("NFKC", answer).strip().lower()
    # Collapse runs of whitespace.
    a = " ".join(a.split())
    return a


def password_strength_score(password: str) -> int:
    """Crude 0-4 strength score for UX display only."""
    if not password:
        return 0
    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1
    if len(password) < 8:
        return 0
    if len(password) < 12:
        return 1
    if classes < 3:
        return 1
    if len(password) < 16:
        return 2
    if classes < 4:
        return 3
    return 4
