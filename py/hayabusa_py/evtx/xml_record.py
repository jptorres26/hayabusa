"""Convert an event rendered as XML (``EvtRender(EvtRenderEventXml)`` on Windows, or an
``evtx_dump -o xml`` record) into the JSON layout Hayabusa's rules and output code expect: the
``evtx`` crate's ``JsonOutput`` with ``separate_json_attributes(true)`` (a port of
``hayabusa-evtx/src/json_output.rs``).

Layout summary::

    <Event xmlns="..."><System><Provider Name="P" Guid="{G}"/>...   ->
    {"Event_attributes": {"xmlns": "..."},
     "Event": {"System": {"Provider_attributes": {"Name": "P", "Guid": "G"}, ...

* an element with attributes becomes ``<name>_attributes: {...}`` next to ``<name>`` (which is
  omitted when the element has no content);
* ``<Data Name="X">v</Data>`` / ``<ComplexData Name="X">`` become ``"X": "v"``; an empty one is
  ``""``; unnamed ``<Data>`` elements collect into a ``"Data"`` array;
* repeated child names get ``_1``, ``_2`` ... suffixes (newest value keeps the bare name);
* text is a string; the binxml types the crate knows are gone in XML, so the System fields the
  crate always renders as integers (EventID, Version, Level, Task, Opcode, EventRecordID,
  Qualifiers, ProcessID, ThreadID) are converted back, everything else stays a string. The
  engine compares field text, so this only changes the compact-JSON form keyword rules grep.

``wevtapi`` mode additionally normalizes the cosmetic differences between the Windows renderer
and the crate: braced lowercase GUIDs -> bare uppercase, 7-digit timestamp fractions -> 6.
"""

from __future__ import annotations

import re
from typing import Any
from xml.parsers import expat

_INT_SYSTEM_ELEMENTS = frozenset({"EventID", "Version", "Level", "Task", "Opcode", "EventRecordID"})
_INT_ATTRIBUTES = frozenset({"Qualifiers", "ProcessID", "ThreadID"})
_DATA_ELEMENTS = frozenset({"Data", "ComplexData"})

_BRACED_GUID_RE = re.compile(r"^\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$")
_TIMESTAMP_7_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6})\d(Z?)$")
_TIMESTAMP_SHORT_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,5}))?(Z?)$")


def _to_int(text: str) -> Any:
    try:
        return int(text)
    except ValueError:
        return text


def normalize_wevtapi_value(text: str) -> str:
    """Windows renders GUIDs as ``{lower-case}`` and timestamps with 7 fraction digits; the
    crate renders bare upper-case GUIDs and exactly 6 digits."""
    if len(text) == 38 and text[0] == "{" and _BRACED_GUID_RE.match(text):
        return text[1:-1].upper()
    if len(text) >= 20 and text[4] == "-" and "T" in text:
        match = _TIMESTAMP_7_RE.match(text)
        if match:
            return match.group(1) + match.group(2)
        match = _TIMESTAMP_SHORT_RE.match(text)
        if match:
            return f"{match.group(1)}.{(match.group(2) or '').ljust(6, '0')}{match.group(3)}"
    return text


class _JsonBuilder:
    """The crate's ``JsonOutput`` state machine (separate-attributes mode)."""

    __slots__ = ("root", "stack")

    def __init__(self) -> None:
        self.root: dict[str, Any] = {}
        self.stack: list[str] = []

    # -- path helpers -------------------------------------------------------------------

    def _walk(self, keys: list[str]) -> Any:
        """``get_or_create_current_path``: return the value at ``keys``, creating objects."""
        holder: Any = None
        holder_key: str | None = None
        current: Any = self.root
        for key in keys:
            if not isinstance(current, dict):
                if current is None:
                    # <System> has null, not an empty map, when it had no attributes.
                    current = {key: {}}
                else:
                    # Character nodes between XML nodes: shift the text under the new key.
                    current = {key: current}
                if holder is None:
                    self.root = current
                else:
                    holder[holder_key] = current
            elif key not in current:
                current[key] = {}
            holder, holder_key = current, key
            current = current[key]
        return current

    def _parent(self) -> dict[str, Any]:
        """``get_current_parent``: the container holding the current element's value."""
        self._walk(self.stack)
        parent = self._walk(self.stack[:-1])
        if not isinstance(parent, dict):
            raise ValueError("expected the parent container to be an object")
        return parent

    def _set_current(self, value: Any) -> None:
        parent = self._walk(self.stack[:-1])
        parent[self.stack[-1]] = value

    # -- element handling ---------------------------------------------------------------

    def _insert_without_attributes(self, name: str) -> None:
        self.stack.append(name)
        container = self._parent()
        old_value = container.get(name, _ABSENT)
        container[name] = None
        if old_value is _ABSENT or old_value is None:
            return
        if isinstance(old_value, dict) and not old_value:
            return
        free_slot = 1
        while f"{name}_{free_slot}" in container:
            free_slot += 1
        container[f"{name}_{free_slot}"] = old_value

    def _insert_with_attributes(self, name: str, attributes: dict[str, Any]) -> None:
        self.stack.append(name)
        container = self._parent()
        if attributes:
            attr_key = f"{name}_attributes"
            old_attribute = container.get(attr_key, _ABSENT)
            container[attr_key] = None
            if old_attribute is not _ABSENT:
                old_value = container.get(name, _ABSENT)
                container[name] = None
                if old_value is not _ABSENT:
                    free_slot = 1
                    while f"{name}_{free_slot}" in container or f"{name}_{free_slot}_attributes" in container:
                        free_slot += 1
                    if isinstance(old_value, dict) and old_value:
                        container[f"{name}_{free_slot}"] = old_value
                    if isinstance(old_attribute, dict) and old_attribute:
                        container[f"{name}_{free_slot}_attributes"] = old_attribute
            container[attr_key] = attributes
            current = container.get(name, _ABSENT)
            if current is None or (isinstance(current, dict) and not current):
                container.pop(name, None)
        else:
            container[name] = None

    def open_element(self, name: str, attributes: dict[str, Any]) -> None:
        if name in _DATA_ELEMENTS:
            data_name = attributes.get("Name")
            if data_name is not None:
                self._insert_without_attributes(str(data_name))
            else:
                self.stack.append(name)
            return
        if not attributes:
            self._insert_without_attributes(name)
        else:
            self._insert_with_attributes(name, attributes)

    def characters(self, value: Any) -> None:
        current = self._walk(self.stack)
        if current is None:
            self._set_current(value)
        elif isinstance(current, dict):
            if not current:
                self._set_current(value)
            # else: the crate discards text mixed into an element that already has children
        elif isinstance(current, str):
            self._set_current(current + (value if isinstance(value, str) else str(value)))
        elif isinstance(current, list):
            current.append(value)
        else:
            raise ValueError(f"expected the current value to be a string or an array, found {current!r}")

    def close_element(self, name: str, attributes: dict[str, Any]) -> None:
        if name in _DATA_ELEMENTS:
            data_name = attributes.get("Name")
            if data_name is not None:
                parent = self._parent()
                if parent.get(str(data_name), _ABSENT) is None:
                    parent[str(data_name)] = ""
        self.stack.pop()


_ABSENT: Any = object()


class _Frame:
    __slots__ = ("attributes", "has_children", "name", "text", "unnamed_data")

    def __init__(self, name: str, attributes: dict[str, Any]) -> None:
        self.name = name
        self.attributes = attributes
        self.text: list[str] = []
        self.has_children = False
        self.unnamed_data = name in _DATA_ELEMENTS and "Name" not in attributes


class XmlRecordParser:
    """Feed one event's XML to :meth:`parse`; get the record dict back.

    ``wevtapi`` selects the Windows-renderer normalizations (GUID braces, 7-digit fractions).
    """

    __slots__ = ("_builder", "_frames", "_wevtapi")

    def __init__(self, *, wevtapi: bool = False) -> None:
        self._wevtapi = wevtapi
        self._builder = _JsonBuilder()
        self._frames: list[_Frame] = []

    def parse(self, xml_text: str | bytes) -> dict[str, Any]:
        self._builder = _JsonBuilder()
        self._frames = []
        parser = expat.ParserCreate(None, None)
        parser.buffer_text = True
        parser.ordered_attributes = True
        parser.StartElementHandler = self._start
        parser.EndElementHandler = self._end
        parser.CharacterDataHandler = self._chars
        if isinstance(xml_text, str):
            xml_text = xml_text.encode("utf-8")
        parser.Parse(xml_text, True)
        return self._builder.root

    # expat callbacks --------------------------------------------------------------------

    def _start(self, name: str, attr_list: list[str]) -> None:
        if self._frames:
            parent = self._frames[-1]
            parent.has_children = True
            self._flush_text(parent, before_child=True)
        attributes: dict[str, Any] = {}
        for index in range(0, len(attr_list), 2):
            key = attr_list[index]
            value = attr_list[index + 1]
            if self._wevtapi:
                value = normalize_wevtapi_value(value)
            if key in _INT_ATTRIBUTES:
                value = _to_int(value)
            attributes[key] = value
        frame = _Frame(name, attributes)
        self._frames.append(frame)
        if frame.unnamed_data:
            # Unnamed <Data> elements collect into an array (the crate's StringArrayType).
            builder = self._builder
            builder.stack.append(name)
            container = builder._parent()
            existing = container.get(name, _ABSENT)
            if not isinstance(existing, list):
                container[name] = []
            return
        self._builder.open_element(name, attributes)

    def _chars(self, data: str) -> None:
        if self._frames:
            self._frames[-1].text.append(data)

    def _end(self, name: str) -> None:
        frame = self._frames.pop()
        builder = self._builder
        if frame.unnamed_data:
            text = "".join(frame.text)
            if frame.has_children and text.strip() == "":
                text = ""
            elif "\n" in text and text.strip() == "":
                text = ""  # pretty-printed whitespace (evtx_dump); wevtapi emits none
            if self._wevtapi:
                text = normalize_wevtapi_value(text)
            container = builder._parent()
            container[name].append(text)
            builder.stack.pop()
            return
        parent_name = self._frames[-1].name if self._frames else ""
        self._flush_text(frame, before_child=False, parent_name=parent_name)
        builder.close_element(name, frame.attributes)

    def _flush_text(self, frame: _Frame, *, before_child: bool, parent_name: str = "") -> None:
        if not frame.text:
            return
        text = "".join(frame.text)
        frame.text = []
        if text.strip() == "" and (frame.has_children or "\n" in text):
            return  # indentation between child elements
        if self._wevtapi:
            text = normalize_wevtapi_value(text)
        value: Any = text
        if not before_child and parent_name == "System" and frame.name in _INT_SYSTEM_ELEMENTS:
            value = _to_int(text)
        self._builder.characters(value)


def xml_to_record(xml_text: str | bytes, *, wevtapi: bool = False) -> dict[str, Any]:
    """One-shot helper around :class:`XmlRecordParser`."""
    return XmlRecordParser(wevtapi=wevtapi).parse(xml_text)
