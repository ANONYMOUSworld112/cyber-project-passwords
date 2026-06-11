"""Shared pytest fixtures."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

import pytest


@pytest.fixture
def tmp_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Redirect csp to a fresh data directory for each test."""
    d = tmp_path / "csp-data"
    monkeypatch.setenv("CSP_DATA_DIR", str(d))
    yield d
