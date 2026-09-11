"""EVTX reader built on the Windows Event Log API (``wevtapi.dll`` through ``pywin32``).

This is the only OS-specific part of the engine and the reason the "no Rust" design works:
Microsoft's own parser reads the file, so there is no third-party binary-format code to keep
current. ``EvtQuery`` opens the file, ``EvtNext`` walks it in batches, ``EvtRender`` produces the
event XML, and :mod:`hayabusa_py.evtx.xml_record` converts that into the record layout the rules
and output code expect.

Known difference from Hayabusa: the Rust ``evtx`` crate recovers records from damaged chunks and
reports them as recovered records; the Windows API does not expose them, so a corrupt file yields
the records the service can read plus an error, never a partial silent result
(:class:`EvtxReadError` carries the Windows error code).

Everything here is import-safe on non-Windows: ``win32evtlog`` is imported on first use, so the
module can be imported (and its logic tested with a stub API) anywhere.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hayabusa_py.evtx.errors import EvtxReadError
from hayabusa_py.evtx.xml_record import XmlRecordParser

__all__ = [
    "EvtxReadError",
    "ReadStats",
    "check_evtx_header",
    "iter_evtx_records",
    "record_count",
    "record_id_query",
]

EVTX_MAGIC = b"ElfFile\x00"

# EVT_QUERY_FLAGS / EVT_RENDER_FLAGS / EVT_OPEN_LOG_FLAGS, repeated here so the module imports
# and its query strings can be tested without pywin32 present.
EVT_QUERY_FILE_PATH = 0x2
EVT_QUERY_FORWARD_DIRECTION = 0x100
EVT_QUERY_TOLERATE_QUERY_ERRORS = 0x1000
EVT_RENDER_EVENT_XML = 1
EVT_OPEN_FILE_PATH = 0x2
EVT_LOG_NUMBER_OF_LOG_RECORDS = 3

ERROR_NO_MORE_ITEMS = 259

_API: Any = None


def _api() -> Any:
    """The ``win32evtlog`` module, imported on first use (tests substitute a stub)."""
    global _API
    if _API is None:
        import win32evtlog  # noqa: PLC0415  (Windows-only import, deliberately deferred)

        _API = win32evtlog
    return _API


@dataclass(slots=True)
class ReadStats:
    """What a read produced, for the job log: totals plus per-record render failures."""

    records: int = 0
    render_errors: int = 0
    first_error: str = ""


def check_evtx_header(path: str | Path) -> None:
    """Raise :class:`EvtxReadError` unless the file starts with the EVTX signature.

    The API's own error for a non-EVTX file is generic; technicians upload the wrong file often
    enough that it is worth saying so plainly.
    """
    try:
        with open(path, "rb") as handle:
            magic = handle.read(8)
    except OSError as exc:
        raise EvtxReadError(str(path), f"cannot be opened ({exc.strerror or exc})") from exc
    if magic != EVTX_MAGIC:
        raise EvtxReadError(str(path), "is not an EVTX file (missing the 'ElfFile' signature)")


def record_id_query(start: int | None = None, stop: int | None = None) -> str:
    """XPath selecting a half-open ``EventRecordID`` range, for splitting one file across workers.

    ``*`` (all records) when neither bound is given. Windows Event Log accepts a small subset of
    XPath 1.0; comparisons on ``System/EventRecordID`` are inside it. The query goes to
    ``EvtQuery`` as a plain XPath string, so ``>=`` and ``<`` are written literally (they would
    only need escaping inside a structured XML ``<Select>`` element).
    """
    tests = []
    if start is not None:
        tests.append(f"EventRecordID >= {int(start)}")
    if stop is not None:
        tests.append(f"EventRecordID < {int(stop)}")
    if not tests:
        return "*"
    return f"*[System[{' and '.join(tests)}]]"


def record_count(path: str | Path) -> int:
    """Number of records in the file, from ``EvtGetLogInfo`` (no parsing)."""
    api = _api()
    handle = None
    try:
        handle = api.EvtOpenLog(str(path), EVT_OPEN_FILE_PATH)
        value, _type = api.EvtGetLogInfo(handle, EVT_LOG_NUMBER_OF_LOG_RECORDS)
        return int(value)
    except Exception as exc:  # noqa: BLE001 - normalized below
        raise _as_read_error(path, exc) from exc
    finally:
        _close(handle)


def iter_evtx_records(
    path: str | Path,
    *,
    query: str = "*",
    batch_size: int = 512,
    timeout_ms: int = 30_000,
    stats: ReadStats | None = None,
    on_error: Callable[[str], None] | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield every record of ``path`` in file order, in the engine's record layout.

    A record that cannot be rendered is counted in ``stats`` and reported through ``on_error``
    rather than aborting the file: one unreadable event should not lose the other 500,000.
    A file that cannot be opened raises :class:`EvtxReadError`.
    """
    check_evtx_header(path)
    api = _api()
    stats = stats if stats is not None else ReadStats()
    parser = XmlRecordParser(wevtapi=True)
    flags = EVT_QUERY_FILE_PATH | EVT_QUERY_FORWARD_DIRECTION | EVT_QUERY_TOLERATE_QUERY_ERRORS
    result_set = None
    try:
        try:
            result_set = api.EvtQuery(str(path), flags, query, None)
        except Exception as exc:  # noqa: BLE001 - normalized below
            raise _as_read_error(path, exc) from exc
        while True:
            try:
                events = api.EvtNext(result_set, batch_size, timeout_ms, 0)
            except Exception as exc:  # noqa: BLE001 - normalized below
                if _winerror(exc) == ERROR_NO_MORE_ITEMS:
                    return
                raise _as_read_error(path, exc) from exc
            if not events:
                return
            for event in events:
                try:
                    xml = api.EvtRender(event, EVT_RENDER_EVENT_XML)
                    record = parser.parse(xml)
                except Exception as exc:  # noqa: BLE001 - one bad event must not end the file
                    stats.render_errors += 1
                    detail = f"{path}: a record could not be rendered: {exc}"
                    if not stats.first_error:
                        stats.first_error = detail
                    if on_error is not None:
                        on_error(detail)
                    continue
                finally:
                    _close(event)
                stats.records += 1
                yield record
    finally:
        _close(result_set)


def _close(handle: Any) -> None:
    if handle is None:
        return
    try:
        handle.Close()
    except Exception:  # noqa: BLE001, S110 - a handle that will not close is not actionable
        pass


def _winerror(exc: BaseException) -> int | None:
    value = getattr(exc, "winerror", None)
    if isinstance(value, int):
        return value
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int):
        return args[0]
    return None


def _as_read_error(path: str | Path, exc: BaseException) -> EvtxReadError:
    """Turn a ``pywintypes.error`` into an :class:`EvtxReadError` with a readable message."""
    code = _winerror(exc)
    detail = getattr(exc, "strerror", None)
    if not detail:
        args = getattr(exc, "args", ())
        detail = str(args[-1]) if args else str(exc)
    if code == 5:
        detail = f"{detail} (the service account needs read access to the file)"
    elif code == 32:
        detail = f"{detail} (the file is in use; export a copy with `wevtutil epl` first)"
    return EvtxReadError(str(path), str(detail).strip().rstrip("."), code)
