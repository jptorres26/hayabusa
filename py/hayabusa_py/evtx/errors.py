"""Errors the readers raise, in their own module so the CLI and the service can catch them
without importing the Windows-only reader."""

from __future__ import annotations


class EvtxReadError(Exception):
    """A log file could not be opened or read.

    ``winerror`` is the Windows error code when the failure came from the Event Log API, and
    ``None`` when it did not (a missing file, a file that is not EVTX at all).
    """

    def __init__(self, path: str, message: str, winerror: int | None = None) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message
        self.winerror = winerror
