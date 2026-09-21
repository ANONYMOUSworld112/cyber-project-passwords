"""Best-effort in-memory zeroization.

CPython usually frees memory promptly, but for sensitive material we
try to overwrite the buffer before letting it go. The ``bytearray``
mutation is reliable; ``bytes`` objects are immutable, so we use a
``bytearray`` shim in :class:`WipedBuffer`.

This is not a perfect defense (the OS may have already swapped the
memory), but it materially raises the bar compared to leaving the
key in a long-lived immutable string.
"""

from __future__ import annotations

from typing import Union


def wipe(buf: Union[bytearray, memoryview, list]) -> None:
    """Overwrite the contents of ``buf`` with zeros, where possible."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, memoryview):
        mv = buf.cast("B")
        for i in range(len(mv)):
            mv[i] = 0
    elif isinstance(buf, list):
        for i in range(len(buf)):
            if isinstance(buf[i], int):
                buf[i] = 0


class SecretBuffer:
    """A mutable container for secret bytes that can be wiped."""

    __slots__ = ("_buf",)

    def __init__(self, data: bytes) -> None:
        self._buf = bytearray(data)

    def get(self) -> bytes:
        return bytes(self._buf)

    def wipe(self) -> None:
        wipe(self._buf)

    def __len__(self) -> int:
        return len(self._buf)
