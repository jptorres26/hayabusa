"""Keep a timeline on disk instead of in memory while it is being built.

A scan's memory is dominated by rendered rows, not by the log: roughly 11 KB per detection, held
until the timeline can be sorted. That is fine for a corpus scan and not fine for a service that
accepts uploads up to its configured cap -- a noisy multi-gigabyte Security log could produce
enough detections to exhaust the machine, and an out-of-memory kill takes the worker down with
the job rather than failing the job cleanly.

So rows are written out in sorted runs as they are produced and merged when the results are
written. Memory is bounded by the flush interval rather than by the number of detections, and the
output is identical to sorting everything in memory: ``heapq.merge`` over sorted runs reproduces
exactly the order :func:`hayabusa_py.output.writers.sort_key` defines.
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

    __slots__ = ("_buffer", "_directory", "_files", "_flush_rows", "_owned", "_rows")

    def __init__(self, directory: Path | None = None, *, flush_rows: int = 20_000, own_directory: bool = True) -> None:
        if directory is not None:
            Path(directory).mkdir(parents=True, exist_ok=True)
        self._directory = Path(tempfile.mkdtemp(prefix="hayabusa-spool-", dir=directory))
        self._files: list[Path] = []
        self._buffer: list[DetectInfo] = []
        self._flush_rows = max(1, flush_rows)
        self._owned = own_directory
        self._rows = 0

    def __enter__(self) -> RowSpool:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    @property
    def rows(self) -> int:
        """Rows added so far, whether or not they have been flushed."""
        return self._rows

    @property
    def files(self) -> int:
        return len(self._files)

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def paths(self) -> list[Path]:
        """The finished run files, for a caller that will merge them itself."""
        self.flush()
        return list(self._files)

    def write(self, row: DetectInfo) -> None:
        """Add one row, flushing a sorted run once the buffer reaches the flush interval."""
        self._buffer.append(row)
        self._rows += 1
        if len(self._buffer) >= self._flush_rows:
            self.flush()

    def flush(self) -> None:
        """Write whatever is buffered as one sorted run."""
        if self._buffer:
            buffered, self._buffer = self._buffer, []
            self._write_run(buffered)

    def add(self, rows: Iterable[DetectInfo]) -> int:
        """Write a whole batch as sorted runs. Returns how many rows it held."""
        count = 0
        for row in rows:
            self.write(row)
            count += 1
        return count

    def _write_run(self, batch: list[DetectInfo]) -> None:
        batch.sort(key=sort_key)
        path = self._directory / f"{len(self._files):05d}.spool"
        with open(path, "wb") as handle:
            for row in batch:
                pickle.dump(row, handle, protocol=pickle.HIGHEST_PROTOCOL)
        self._files.append(path)

    def merged(self) -> Iterator[DetectInfo]:
        """Every row, in timeline order, reading one row at a time from each run."""
        self.flush()
        yield from merge_spools(self._files)

    def close(self) -> None:
        self._buffer = []
        if self._owned:
            shutil.rmtree(self._directory, ignore_errors=True)
        self._files = []


def merge_spools(paths: Iterable[Path]) -> Iterator[DetectInfo]:
    """Merge already-sorted run files into one timeline-ordered stream."""
    handles = [open(path, "rb") for path in paths]  # noqa: SIM115 - closed below
    try:
        yield from heapq.merge(*(_read_rows(handle) for handle in handles), key=sort_key)
    finally:
        for handle in handles:
            handle.close()


def _read_rows(handle) -> Iterator[DetectInfo]:  # noqa: ANN001
    while True:
        try:
            yield pickle.load(handle)
        except EOFError:
            return
