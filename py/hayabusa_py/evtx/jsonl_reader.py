"""Readers for records already in JSON form: ``evtx_dump`` JSONL fixtures and Hayabusa's
``-J/--json-input`` files (``.json`` arrays or ``.jsonl``)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def iter_jsonl_records(path: str | Path) -> Iterator[Any]:
    """Yield one record (JSON object) per non-empty line of a JSONL file."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def iter_json_records(path: str | Path) -> Iterator[Any]:
    """Yield records from a ``.json`` file holding an array of objects, a single object, or
    concatenated objects (``jq -c`` style), and from ``.jsonl`` files."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if str(path).endswith(".jsonl") or not stripped.startswith("["):
        decoder = json.JSONDecoder()
        index = 0
        length = len(text)
        while index < length:
            while index < length and text[index].isspace():
                index += 1
            if index >= length:
                break
            value, index = decoder.raw_decode(text, index)
            yield value
        return
    loaded = json.loads(text)
    if isinstance(loaded, list):
        yield from loaded
    else:
        yield loaded


def normalize_evtx_dump(value: Any) -> Any:
    """Map ``evtx_dump`` (evtx crate 0.12) JSON onto the layout Hayabusa's bundled evtx 0.9 fork
    produces: an element that only has text content is emitted by 0.12 as ``{"#text": ...}``
    (e.g. the unnamed ``<Data>`` elements of EventData), whereas 0.9 emits the text/array itself.

    Known, unrecoverable difference: 0.12 emits ``null`` for every empty element, while 0.9
    distinguishes an empty string value (``""``) from an empty binary value (``null``). It only
    affects whether an empty field is listed in AllFieldInfo/ExtraFieldInfo.
    """
    if isinstance(value, dict):
        if len(value) == 1 and "#text" in value:
            return normalize_evtx_dump(value["#text"])
        out = {}
        for key, item in value.items():
            if key == "Data" and isinstance(item, dict) and len(item) == 1 and "#text" in item and not isinstance(item["#text"], list):
                # A single unnamed <Data> element: 0.9 emits a one-element array (an empty one
                # becomes null), 0.12 collapses it to the bare text.
                text = item["#text"]
                out[key] = None if text in ("", None) else [text]
            else:
                out[key] = normalize_evtx_dump(item)
        return out
    if isinstance(value, list):
        return [normalize_evtx_dump(item) for item in value]
    return value


def iter_fixture_records(path: str | Path) -> Iterator[Any]:
    """``evtx_dump`` JSONL fixture records, normalized to Hayabusa's record layout."""
    for record in iter_jsonl_records(path):
        yield normalize_evtx_dump(record)


def normalize_json_input(record: Any) -> Any:
    """Hayabusa's ``-J`` accepts records that are the bare ``Event`` object; wrap them."""
    if isinstance(record, dict) and "Event" not in record and "System" in record:
        return {"Event": record}
    return record
