"""JSON value helpers with ``serde_json`` semantics (port of parts of ``src/detections/utils.rs``).

Event records are plain Python objects produced by ``json.loads`` (dict/list/str/int/float/bool/None)
in the layout the Rust ``evtx`` crate emits with ``separate_json_attributes(true)``, e.g.::

    {"Event": {"System": {"Channel": "Security", "EventID": 4624,
                          "TimeCreated_attributes": {"SystemTime": "2021-12-23T00:00:00.000000Z"},
                          "Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
               "EventData": {"TargetUserName": "Administrator", "LogonType": 3}}}
"""

from __future__ import annotations

import json
import math
from typing import Any

from hayabusa_py.rules.config import EventKeyAlias

JsonValue = Any


def json_compact(value: JsonValue) -> str:
    """``serde_json::Value::to_string()``: compact JSON, non-ASCII kept as-is."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _number_to_string(value: int | float) -> str:
    if isinstance(value, bool):  # pragma: no cover - callers exclude bool before reaching here
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    # serde_json renders finite floats with ryu ("1.0", "0.1", "1e20", "1e-7"); Python's repr is
    # the same shortest round-trip form except for the exponent spelling, normalized here.
    if not math.isfinite(value):
        return "null"
    text = repr(value)
    if "e" in text:
        mantissa, exponent = text.split("e")
        sign = "-" if exponent.startswith("-") else ""
        text = f"{mantissa}e{sign}{exponent.lstrip('+-').lstrip('0') or '0'}"
    return text


def value_to_string(value: JsonValue) -> str | None:
    """``utils::value_to_string``: scalar -> trimmed string; null/array/object -> None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number_to_string(value)
    if isinstance(value, str):
        return value.strip()
    return None


def serde_number_to_string(value: JsonValue, search_flag: bool = False) -> str | None:
    """``utils::get_serde_number_to_string``.

    Strings are returned untouched (not trimmed); null and objects give None (objects are
    flattened to ``key:value ¦ key:value`` only when ``search_flag`` is set); every other value
    is rendered as its JSON text (so arrays become e.g. ``["a","b"]``).
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if not search_flag:
            return None
        return " ¦ ".join(f"{k}:{json_compact(v)}".replace('"', "") for k, v in value.items())
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number_to_string(value)
    return json_compact(value)


class _Missing:
    """Sentinel for ``utils::get_event_value`` returning Rust ``None``: the path could not be
    walked because a segment had to be looked up on a non-object (or the key was empty).

    This is distinct from a JSON ``null`` / absent *final* key, which Rust reports as
    ``Some(Value::Null)`` and Python as ``None``. Only the count() grouping code tells the two
    apart (a missing final key groups under ``"null"``); everything else treats both as no value.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover
        return "MISSING"


MISSING: Any = _Missing()


def get_event_value(key: str, record: JsonValue, alias: EventKeyAlias) -> JsonValue:
    """``utils::get_event_value``: resolve ``key`` through the alias table or as a dotted path.

    Keys without an alias and without a dot are looked up under ``Event.EventData``.
    Returns :data:`MISSING` when a segment must be indexed on a non-object, and ``None`` when the
    final key is absent or holds JSON null (see :class:`_Missing`).
    """
    if not key:
        return MISSING
    event_key = alias.get(key)
    if event_key is None:
        event_key = key if "." in key else "Event.EventData." + key
    current = record
    for segment in event_key.split("."):
        if not isinstance(current, dict):
            return MISSING
        current = current.get(segment)
    return current


def walk_path(record: JsonValue, path: str) -> tuple[JsonValue, str]:
    """The lenient walk used by ``message::parse_message``: follow each segment that exists,
    ignore the ones that do not, and report the last segment that resolved."""
    current = record
    field = ""
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
            field = segment
    return current, field
