"""Custom exceptions for csp.

All exceptions inherit from CSPError so callers can catch a single base
class. The hierarchy is split between "user-fixable" errors (bad password,
unknown user) and "internal" errors (corrupt vault, IO failure).
"""

from __future__ import annotations


class CSPError(Exception):
    """Base class for all csp errors."""


class UserError(CSPError):
    """User input is wrong or the action is not allowed."""


class AuthError(UserError):
    """Authentication failed: wrong password, locked out, etc."""


class LockedOutError(AuthError):
    """Account is temporarily locked due to too many failed attempts."""


class StaleLockError(UserError):
    """A lock file from a dead process was found; user must clear it."""

    def __init__(self, pid: int) -> None:
        super().__init__(
            f"Stale lock from pid {pid}. Run 'csp lock --force' to clear."
        )
        self.pid = pid


class ActiveSessionError(UserError):
    """Another csp REPL is already active."""

    def __init__(self, pid: int, user: str) -> None:
        super().__init__(
            f"Another csp session is active (pid {pid} as {user}). "
            f"Run 'csp lock --force' only if that process is dead."
        )
        self.pid = pid
        self.user = user


class SetupError(UserError):
    """First-time setup could not complete."""


class NotInitializedError(UserError):
    """Application has not been set up yet."""


class AlreadyInitializedError(UserError):
    """Setup was already completed."""


class VaultError(CSPError):
    """Vault data is missing, corrupt, or undecryptable."""


class CorruptVaultError(VaultError):
    """Decryption succeeded in shape but content is invalid."""


class FeatureError(UserError):
    """A feature command was misused or its data is missing."""
