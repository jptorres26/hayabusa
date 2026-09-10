"""Timestamps with nanosecond precision (evtx ``SystemTime`` carries 100 ns ticks, which
``datetime`` cannot represent). Port of ``utils::str_time_to_datetime``, ``utils::format_time``
and ``message::get_event_time``.

A timestamp is an ``int`` of nanoseconds since the Unix epoch, UTC.
"""

from __future__ import annotations

import calendar
import re
import time as _time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

NANOS = 1_000_000_000

_RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?\s*([Zz]|[+-]\d{2}:\d{2})$"
)


def parse_rfc3339_ns(text: str) -> int | None:
    """``DateTime::parse_from_rfc3339`` -> epoch nanoseconds (UTC), or None when unparsable."""
    if not text:
        return None
    match = _RFC3339_RE.match(text)
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    try:
        seconds = calendar.timegm((int(year), int(month), int(day), int(hour), int(minute), int(second), 0, 0, 0))
        datetime(int(year), int(month), int(day), int(hour), int(minute), min(int(second), 59))
    except (ValueError, OverflowError):
        return None
    nanos = int((fraction or "0").ljust(9, "0"))
    if offset not in ("Z", "z"):
        sign = 1 if offset[0] == "+" else -1
        seconds -= sign * (int(offset[1:3]) * 3600 + int(offset[4:6]) * 60)
    return seconds * NANOS + nanos


def get_event_time(record: Any, json_input_flag: bool = False) -> int | None:
    """``message::get_event_time``: ``Event.System.TimeCreated_attributes.SystemTime`` (or
    ``Event.System.@timestamp`` for JSON input) as epoch nanoseconds."""
    try:
        system = record["Event"]["System"]
        text = system["@timestamp"] if json_input_flag else system["TimeCreated_attributes"]["SystemTime"]
    except (KeyError, TypeError):
        return None
    if not isinstance(text, str):
        return None
    return parse_rfc3339_ns(text)


EPOCH_1970_NS = 0
EPOCH_1977_NS = calendar.timegm((1977, 1, 1, 0, 0, 0, 0, 0, 0)) * NANOS


@dataclass(slots=True, frozen=True)
class TimeFormatOptions:
    """The ``--utc/--iso-8601/--rfc-2822/...`` flags (``configs::TimeFormatOptions``)."""

    utc: bool = False
    iso_8601: bool = False
    rfc_2822: bool = False
    rfc_3339: bool = False
    us_time: bool = False
    us_military_time: bool = False
    european_time: bool = False

    def is_utc_output(self) -> bool:
        return self.utc or self.iso_8601


UTC_OPTIONS = TimeFormatOptions(utc=True)


def _local_offset_seconds(epoch_seconds: int) -> int:
    local = _time.localtime(epoch_seconds)
    return local.tm_gmtoff


def _fixed_offset_text(offset_seconds: int) -> str:
    sign = "+" if offset_seconds >= 0 else "-"
    offset_seconds = abs(offset_seconds)
    return f"{sign}{offset_seconds // 3600:02d}:{(offset_seconds % 3600) // 60:02d}"


def _auto_fraction(nanos: int) -> str:
    """chrono ``%.f``: 3, 6 or 9 digits depending on precision, with the leading dot."""
    if nanos % 1_000_000 == 0:
        return f".{nanos // 1_000_000:03d}"
    if nanos % 1_000 == 0:
        return f".{nanos // 1_000:06d}"
    return f".{nanos:09d}"


def format_time(epoch_ns: int, date_only: bool, options: TimeFormatOptions) -> str:
    """``utils::format_time`` / ``format_rfc``: render a timestamp per the output options."""
    seconds, nanos = divmod(epoch_ns, NANOS)
    if options.is_utc_output():
        offset = 0
    else:
        offset = _local_offset_seconds(seconds)
    dt = datetime.fromtimestamp(seconds, UTC).replace(tzinfo=None) + timedelta(seconds=offset)
    tz = _fixed_offset_text(offset)
    millis = f"{nanos // 1_000_000:03d}"
    micros = f"{nanos // 1_000:06d}"
    if options.rfc_2822:
        if date_only:
            return dt.strftime("%a, ") + f"{dt.day:2d}" + dt.strftime(" %b %Y")
        return dt.strftime("%a, ") + f"{dt.day:2d}" + dt.strftime(" %b %Y %H:%M:%S ") + tz
    if options.rfc_3339:
        if date_only:
            return dt.strftime("%Y-%m-%d")
        return dt.strftime("%Y-%m-%d %H:%M:%S") + "." + micros + tz
    if options.us_time:
        if date_only:
            return dt.strftime("%m-%d-%Y")
        return dt.strftime("%m-%d-%Y %I:%M:%S") + "." + millis + dt.strftime(" %p ") + tz
    if options.us_military_time:
        if date_only:
            return dt.strftime("%m-%d-%Y")
        return dt.strftime("%m-%d-%Y %H:%M:%S") + "." + millis + " " + tz
    if options.european_time:
        if date_only:
            return dt.strftime("%d-%m-%Y")
        return dt.strftime("%d-%m-%Y %H:%M:%S") + "." + millis + " " + tz
    if options.iso_8601:
        if date_only:
            return dt.strftime("%Y-%m-%d")
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + _auto_fraction(nanos) + "Z"
    if date_only:
        return dt.strftime("%Y-%m-%d")
    return dt.strftime("%Y-%m-%d %H:%M:%S") + "." + millis + " " + tz


def to_datetime(epoch_ns: int) -> datetime:
    """Microsecond-precision ``datetime`` (UTC) for code that needs one."""
    seconds, nanos = divmod(epoch_ns, NANOS)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=nanos // 1_000)
