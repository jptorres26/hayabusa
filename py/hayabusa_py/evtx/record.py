"""The per-record structure the engine evaluates (port of ``EvtxRecordInfo`` in
``src/detections/detection.rs``, ``utils::create_rec_info`` and ``src/detections/field_extract.rs``).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from hayabusa_py.engine.values import MISSING, get_event_value, json_compact, value_to_string
from hayabusa_py.rules.config import EventKeyAlias

_POWERSHELL_CLASSIC_EIDS = {"400", "403", "600", "800"}


class RecordInfo:
    """One event record plus the string values the rules look at.

    ``key_to_value`` is filled eagerly by :func:`create_rec_info` (the Rust behaviour) or
    lazily, on first lookup, when the record was built with an alias table (the scan path,
    which avoids resolving hundreds of keys per record that no candidate rule will read).
    The result is identical: a key resolves to the trimmed scalar text of the record field or
    to ``None``.
    """

    __slots__ = ("_alias", "_data_string", "evtx_filepath", "key_to_value", "record", "recovered_record")

    def __init__(
        self,
        evtx_filepath: str,
        record: Any,
        data_string: str | None = None,
        key_to_value: dict[str, str] | None = None,
        recovered_record: bool = False,
        alias: EventKeyAlias | None = None,
    ) -> None:
        self.evtx_filepath = evtx_filepath
        self.record = record
        self._data_string = data_string
        self.key_to_value: dict[str, str | None] = dict(key_to_value) if key_to_value else {}
        self.recovered_record = recovered_record
        self._alias = alias

    @property
    def data_string(self) -> str:
        """Compact JSON text of the record (keyword/grep-style rules match against it)."""
        if self._data_string is None:
            self._data_string = json_compact(self.record)
        return self._data_string

    def get_value(self, key: str) -> str | None:
        cache = self.key_to_value
        if key in cache:
            return cache[key]
        if self._alias is None:
            return None
        value = get_event_value(key, self.record, self._alias)
        text = None if value is MISSING else value_to_string(value)
        cache[key] = text
        return text


def extract_powershell_classic_fields(data: Any, data_index: int, flat_key_to_value: dict[str, Any]) -> dict[str, Any] | None:
    """``field_extract::extract_powershell_classic_fields``: find the EventData ``Data`` array,
    parse element ``data_index`` as ``Key=Value`` lines and merge the pairs next to the array."""
    if isinstance(data, dict):
        extracted: dict[str, Any] | None = None
        for value in data.values():
            extracted = extract_powershell_classic_fields(value, data_index, flat_key_to_value)
            if extracted is not None:
                break
        if isinstance(extracted, dict):
            for key, value in extracted.items():
                data[key] = value
                if isinstance(value, str):
                    flat_key_to_value[key] = value
        return None
    if isinstance(data, list):
        if data_index < len(data) and isinstance(data[data_index], str):
            fields: dict[str, Any] = {}
            for line in data[data_index].strip().split("\n\t"):
                line = line.removesuffix("\r\n")
                line = line.removesuffix("\r")
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                fields[key] = value
            return fields
    return None


def extract_fields(channel: str | None, event_id: str | None, data: Any, flat_key_to_value: dict[str, Any]) -> None:
    """``field_extract::extract_fields``: classic PowerShell events 400/403/600/800 keep their
    useful data as ``Key=Value`` lines inside one ``Data`` array element; surface them as fields."""
    if channel == "Windows PowerShell" and event_id in _POWERSHELL_CLASSIC_EIDS:
        target_index = 1 if event_id == "800" else 2
        extract_powershell_classic_fields(data, target_index, flat_key_to_value)


def create_rec_info(
    data: Any,
    path: str,
    keys: Iterable[str],
    alias: EventKeyAlias,
    *,
    recovered_record: bool = False,
    no_pwsh_field_extraction: bool = False,
) -> RecordInfo:
    """``utils::create_rec_info``: pre-resolve every detection key to its string value."""
    flat_key_to_value: dict[str, str] = {}
    event_id: str | None = None
    channel: str | None = None
    for key in keys:
        value = get_event_value(key, data, alias)
        if value is MISSING:
            continue
        text = value_to_string(value)
        if text is None:
            continue
        if not no_pwsh_field_extraction:
            if key == "EventID":
                event_id = text
            elif key == "Channel":
                channel = text
        flat_key_to_value[key] = text
    if not no_pwsh_field_extraction:
        extract_fields(channel, event_id, data, flat_key_to_value)
    return RecordInfo(
        evtx_filepath=path,
        record=data,
        data_string=json_compact(data),
        key_to_value=flat_key_to_value,
        recovered_record=recovered_record,
    )


def create_lazy_rec_info(
    data: Any,
    path: str,
    alias: EventKeyAlias,
    *,
    recovered_record: bool = False,
    no_pwsh_field_extraction: bool = False,
) -> RecordInfo:
    """Scan-path variant of :func:`create_rec_info`: values are resolved on first use."""
    flat_key_to_value: dict[str, str] = {}
    if not no_pwsh_field_extraction:
        system = data.get("Event", {}).get("System", {}) if isinstance(data, dict) else {}
        if isinstance(system, dict) and system.get("Channel") == "Windows PowerShell":
            event_id = value_to_string(system.get("EventID"))
            extract_fields("Windows PowerShell", event_id, data, flat_key_to_value)
    return RecordInfo(
        evtx_filepath=path,
        record=data,
        key_to_value=flat_key_to_value,
        recovered_record=recovered_record,
        alias=alias,
    )
