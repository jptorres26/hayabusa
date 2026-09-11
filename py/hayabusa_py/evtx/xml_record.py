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
* XML carries no types, so scalars are typed back by :func:`guess_scalar` (see its docstring):
  canonical integers and ``true``/``false`` become JSON numbers and booleans, everything else
  stays a string.

``wevtapi`` mode additionally normalizes the cosmetic differences between the Windows renderer
and the crate: braced lowercase GUIDs -> bare uppercase, 7-digit timestamp fractions -> 6.
"""

from __future__ import annotations

import re
from typing import Any
from xml.parsers import expat

_DATA_ELEMENTS = frozenset({"Data", "ComplexData"})

_BRACED_GUID_RE = re.compile(r"^\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$")
_TIMESTAMP_7_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6})\d(Z?)$")
_TIMESTAMP_SHORT_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,5}))?(Z?)$")


_CANONICAL_INT_RE = re.compile(r"^(?:0|-?[1-9][0-9]{0,19})$")
_INT_MIN, _INT_MAX = -(2**63), 2**64 - 1  # serde_json holds i64 and u64


def guess_scalar(text: str) -> Any:
    """Recover the JSON type the crate would have emitted for this text.

    XML has no types: the crate renders a binxml ``UInt32Type`` and a ``StringType`` holding
    digits identically. It emits numbers and booleans for the former, so text that is a
    canonical i64 or ``true``/``false`` is converted back. On the sample corpus this recovers
    the right type for 98.4% of integers and 97.9% of booleans; the residue is genuinely
    ambiguous (a string field whose value happens to read as a number). The engine compares
    field *text*, and the writers re-derive JSON types from text, so a residual mismatch only
    shows up in the compact-JSON form that keyword rules grep.
    """
    if not text:
        return text
    first = text[0]
    if (first == "-" or first.isdigit()) and _CANONICAL_INT_RE.match(text):
        number = int(text)
        if _INT_MIN <= number <= _INT_MAX:
            return number
    elif first == "t" and text == "true":
        return True
    elif first == "f" and text == "false":
        return False
    return text


_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_PLACEHOLDER = ""
_PLACEHOLDER_BASE = 0xE100
_PLACEHOLDER_RE = re.compile(_PLACEHOLDER + r"([-])")


def _restore_controls(value: Any) -> Any:
    """Undo the placeholder substitution :meth:`XmlRecordParser.parse` applies to C0 controls."""
    if isinstance(value, str):
        if _PLACEHOLDER in value:
            return _PLACEHOLDER_RE.sub(lambda m: chr(ord(m.group(1)) - _PLACEHOLDER_BASE), value)
        return value
    if isinstance(value, dict):
        return {key: _restore_controls(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_restore_controls(item) for item in value]
    return value


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
                    while (
                        f"{name}_{free_slot}" in container
                        or f"{name}_{free_slot}_attributes" in container
                    ):
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
            raise ValueError(
                f"expected the current value to be a string or an array, found {current!r}"
            )

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
    __slots__ = (
        "attributes",
        "had_text",
        "has_children",
        "name",
        "seen_unnamed_data",
        "text",
        "unnamed_data",
    )

    def __init__(self, name: str, attributes: dict[str, Any]) -> None:
        self.name = name
        self.attributes = attributes
        self.text: list[str] = []
        self.had_text = False  # any character data seen, including text already flushed
        self.has_children = False
        self.unnamed_data = name in _DATA_ELEMENTS and "Name" not in attributes
        self.seen_unnamed_data = False  # set on the frame of an unnamed Data: not the first


class XmlRecordParser:
    """Feed one event's XML to :meth:`parse`; get the record dict back.

    ``wevtapi`` selects the Windows-renderer normalizations (GUID braces, 7-digit fractions).
    """

    __slots__ = ("_builder", "_frames", "_pretty", "_unnamed_data", "_wevtapi")

    def __init__(self, *, wevtapi: bool = False, pretty: bool = False) -> None:
        self._wevtapi = wevtapi
        self._pretty = pretty
        self._builder = _JsonBuilder()
        self._frames: list[_Frame] = []
        self._unnamed_data: list[tuple[dict[str, Any], str]] = []

    def parse(self, xml_text: str | bytes) -> dict[str, Any]:
        self._builder = _JsonBuilder()
        self._frames = []
        self._unnamed_data = []
        parser = expat.ParserCreate(None, None)
        parser.buffer_text = True
        parser.ordered_attributes = True
        parser.StartElementHandler = self._start
        parser.EndElementHandler = self._end
        parser.CharacterDataHandler = self._chars
        if isinstance(xml_text, bytes):
            xml_text = xml_text.decode("utf-8", errors="replace")
        if "\r" in xml_text:
            # XML parsers normalize CR/CRLF to LF; the crate keeps the record's own line ends.
            xml_text = xml_text.replace("\r", "&#13;")
        escaped = _CONTROL_CHAR_RE.search(xml_text) is not None
        if escaped:
            # Event fields can hold raw C0 control bytes, which XML cannot represent at all --
            # not even as character references. Carry them through the parser as private-use
            # placeholders and restore them below so no data is lost.
            xml_text = _CONTROL_CHAR_RE.sub(
                lambda m: _PLACEHOLDER + chr(_PLACEHOLDER_BASE + ord(m.group(0))), xml_text
            )
        parser.Parse(xml_text.encode("utf-8"), True)
        for container, key in self._unnamed_data:
            # A single empty <Data/> is an absent value, not a one-element array of "".
            if container.get(key) == [""]:
                container[key] = None
        if escaped:
            return _restore_controls(self._builder.root)
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
            if not value:
                # The crate drops attributes whose binxml value is null, and its XML writer
                # likewise omits empty attribute values, so an empty one carries nothing.
                continue
            if self._wevtapi:
                value = normalize_wevtapi_value(value)
            attributes[key] = guess_scalar(value)
        frame = _Frame(name, attributes)
        if frame.unnamed_data and self._frames:
            parent = self._frames[-1]
            frame.seen_unnamed_data = parent.seen_unnamed_data
            parent.seen_unnamed_data = True
        self._frames.append(frame)
        if frame.unnamed_data:
            # Unnamed <Data> elements hold one binxml array value that the XML renderer expanded
            # into repeated elements, so they collect back into a list under the element's name.
            builder = self._builder
            builder.stack.append(name)
            container = builder._parent()
            if not frame.seen_unnamed_data:
                container[name] = []
                self._unnamed_data.append((container, name))
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
            if self._is_indentation(text, frame):
                text = ""
            if self._wevtapi:
                text = normalize_wevtapi_value(text)
            container = builder._parent()
            container[name].append(text)
            builder.stack.pop()
            return
        parent_name = self._frames[-1].name if self._frames else ""
        self._flush_text(frame, before_child=False, parent_name=parent_name)
        if (
            not frame.had_text
            and not frame.has_children
            and not frame.attributes
            and any(f.name == "UserData" for f in self._frames)
        ):
            # An empty element under UserData: the crate distinguishes an empty *string* value
            # ("") from an absent one (null) by the binxml value type, which XML does not carry.
            # Under UserData the value is a manifest-declared field and "" is right ~95% of the
            # time on the sample corpus (191 vs 11); under EventData null is right (2609 vs 3).
            builder._walk(builder.stack[:-1])[name] = ""
        builder.close_element(name, frame.attributes)

    def _is_indentation(self, text: str, frame: _Frame) -> bool:
        """Whitespace the XML writer added, not event content: anything whitespace-only between
        child elements, and, for pretty-printed input (``evtx_dump``), a newline followed by
        indentation inside an otherwise empty element. A bare ``"\\n"`` is content."""
        if text.strip() != "":
            return False
        if frame.has_children:
            return True
        return self._pretty and text.startswith("\n") and len(text) > 1 and text.strip("\n ") == ""

    def _flush_text(self, frame: _Frame, *, before_child: bool, parent_name: str = "") -> None:
        if not frame.text:
            return
        text = "".join(frame.text)
        frame.text = []
        if self._is_indentation(text, frame):
            return
        if self._wevtapi:
            text = normalize_wevtapi_value(text)
        frame.had_text = True
        self._builder.characters(guess_scalar(text) if not before_child else text)


def xml_to_record(
    xml_text: str | bytes, *, wevtapi: bool = False, pretty: bool = False
) -> dict[str, Any]:
    """One-shot helper around :class:`XmlRecordParser` (``pretty``: indented ``evtx_dump`` XML)."""
    return XmlRecordParser(wevtapi=wevtapi, pretty=pretty).parse(xml_text)
