"""Atomic file writes.

A write is committed by writing to a sibling temp file, fsyncing, then
renaming. On POSIX the rename is atomic; on Windows ``os.replace`` is
atomic on the same volume. Callers are responsible for the parent
directory existing.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]


def atomic_write_bytes(target: Path, data: BytesLike) -> None:
    """Write ``data`` to ``target`` atomically."""
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=target.name + ".",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(data))
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                # fsync can fail on some filesystems; the rename is still
                # the durability guarantee we care about.
                pass
        os.replace(tmp_name, target)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_text(target: Path, text: str, encoding: str = "utf-8") -> None:
    atomic_write_bytes(target, text.encode(encoding))
