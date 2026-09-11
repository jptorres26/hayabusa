"""Keep a job's timeline on disk instead of in memory while it is being built.

A scan's memory is dominated by rendered rows, not by the log: roughly 11 KB per detection, held
until the timeline can be sorted. That is fine for a corpus scan and not fine for a service that
accepts uploads up to its configured cap -- a noisy multi-gigabyte Security log could produce
enough detections to exhaust the machine, and an out-of-memory kill takes the worker down with
the job rather than failing the job cleanly.

So the worker spools each batch of rows to a temporary file, sorted, and merges the files when it
writes the results. Memory is then bounded by the largest single batch plus one row per spool
file, and the output is identical to sorting everything in memory -- ``heapq.merge`` over sorted
inputs is a stable total order, the same one :func:`hayabusa_py.output.writers.sort_key` defines.
"""

from __future__ import annotations

import heapq
import pickle
import shutil
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from types import TracebackType

from hayabusa_py.output.render import DetectInfo
from hayabusa_py.output.writers import sort_key


class RowSpool:
    """Collects rendered rows across batches and yields them in timeline order.

    Use as a context manager; the temporary files are removed on exit, including on failure.
    """

    __slots__ = ("_directory", "_files", "_rows")

    def __init__(self, directory: Path | None = None) -> None:
        self._directory = Path(tempfile.mkdtemp(prefix="hayabusa-spool-", dir=directory))
        self._files: list[Path] = []
        self._rows = 0

    def __enter__(self) -> RowSpool:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    @property
    def rows(self) -> int:
        return self._rows

    @property
    def files(self) -> int:
        return len(self._files)

    def add(self, rows: Iterable[DetectInfo]) -> int:
        """Sort one batch and write it out. Returns how many rows it held."""
        batch = sorted(rows, key=sort_key)
        if not batch:
            return 0
        path = self._directory / f"{len(self._files):05d}.spool"
        with open(path, "wb") as handle:
            for row in batch:
                pickle.dump(row, handle, protocol=pickle.HIGHEST_PROTOCOL)
        self._files.append(path)
        self._rows += len(batch)
        return len(batch)

    def merged(self) -> Iterator[DetectInfo]:
        """Every row, in timeline order, reading one row at a time from each spool file."""
        handles = [open(path, "rb") for path in self._files]  # noqa: SIM115 - closed below
        try:
            yield from heapq.merge(*(_read_rows(handle) for handle in handles), key=sort_key)
        finally:
            for handle in handles:
                handle.close()

    def close(self) -> None:
        shutil.rmtree(self._directory, ignore_errors=True)
        self._files = []


def _read_rows(handle) -> Iterator[DetectInfo]:  # noqa: ANN001
    while True:
        try:
            yield pickle.load(handle)
        except EOFError:
            return
