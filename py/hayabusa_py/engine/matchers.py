"""Leaf matchers and pipe modifiers (port of ``src/detections/rule/matchers/`` plus
``fast_match.rs`` and ``base64_match.rs``).

A leaf of a rule's ``detection`` section is one ``field|modifiers: value`` pair. ``DefaultMatcher``
turns the value into either a *fast match* (plain string operations, used for every real-world
Sigma pattern) or a regular expression, and applies the modifiers listed after the pipes.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hayabusa_py.rules.yaml12 import YamlReal, as_i64, scalar_to_pattern

if TYPE_CHECKING:
    from hayabusa_py.evtx.record import RecordInfo

__all__ = [
    "AllowlistFileMatcher",
    "DefaultMatcher",
    "FastKind",
    "FastMatch",
    "LeafMatcher",
    "MatcherContext",
    "MinlengthMatcher",
    "Pipe",
    "PipeElement",
    "RegexesFileMatcher",
    "concat_selection_key",
    "convert_to_fast_match",
    "wildcard_to_regex",
]


def concat_selection_key(key_list: list[str]) -> str:
    """``utils::concat_selection_key``: human readable path used in error messages."""
    text = "detection -> selection"
    for key in key_list:
        text += " -> " + key
    return text


# --------------------------------------------------------------------------------------------
# ASCII case-insensitive string helpers (fast_match.rs)
# --------------------------------------------------------------------------------------------

_ASCII_LOWER = {code: code + 32 for code in range(ord("A"), ord("Z") + 1)}


def _ascii_lower(text: str) -> str:
    return text.translate(_ASCII_LOWER)


def _byte_len(text: str) -> int:
    return len(text.encode("utf-8", "surrogatepass"))


def eq_ignore_case(event_value: str, match_str: str) -> bool:
    """``fast_match::eq_ignore_case``: ASCII case-insensitive equality (byte lengths must match)."""
    if _byte_len(match_str) != _byte_len(event_value):
        return False
    return _ascii_lower(match_str) == _ascii_lower(event_value)


def starts_with_ignore_case(event_value: str, match_str: str) -> bool | None:
    """None when the event value is not pure ASCII (caller falls back to the regex)."""
    length = _byte_len(match_str)
    if length > _byte_len(event_value):
        return False
    if event_value.isascii():
        return _ascii_lower(match_str) == _ascii_lower(event_value[:length])
    return None


def ends_with_ignore_case(event_value: str, match_str: str) -> bool | None:
    length = _byte_len(match_str)
    event_length = _byte_len(event_value)
    if length > event_length:
        return False
    if event_value.isascii():
        return _ascii_lower(match_str) == _ascii_lower(event_value[event_length - length :])
    return None


# --------------------------------------------------------------------------------------------
# Pipe elements (pipe_element.rs)
# --------------------------------------------------------------------------------------------


class Pipe(Enum):
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    CONTAINS = "contains"
    RE = "re"
    RE_IGNORE_CASE = "reignorecase"
    RE_MULTI_LINE = "remultiline"
    RE_SINGLE_LINE = "resingleline"
    WILDCARD = "wildcard"
    EXPAND = "expand"
    EXISTS = "exists"
    EQUALS_FIELD = "equalsfield"
    ENDSWITH_FIELD = "endswithfield"
    FIELD_REF = "fieldref"
    FIELD_REF_STARTSWITH = "fieldrefstartswith"
    FIELD_REF_ENDSWITH = "fieldrefendswith"
    FIELD_REF_CONTAINS = "fieldrefcontains"
    BASE64 = "base64"
    BASE64_OFFSET = "base64offset"
    WINDASH = "windash"
    CIDR = "cidr"
    ALL = "all"
    ALL_ONLY = "allOnly"
    CASED = "cased"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"
    UTF16 = "utf16"
    UTF16LE = "utf16le"
    UTF16BE = "utf16be"
    WIDE = "wide"


_NUMERIC_PIPES = {Pipe.GT, Pipe.LT, Pipe.GTE, Pipe.LTE}
_FIELD_REF_PIPES = {
    Pipe.EQUALS_FIELD,
    Pipe.ENDSWITH_FIELD,
    Pipe.FIELD_REF,
    Pipe.FIELD_REF_STARTSWITH,
    Pipe.FIELD_REF_ENDSWITH,
    Pipe.FIELD_REF_CONTAINS,
}
_REGEX_PIPES = {Pipe.RE, Pipe.RE_IGNORE_CASE, Pipe.RE_MULTI_LINE, Pipe.RE_SINGLE_LINE}
_USIZE_RE = re.compile(r"^\+?[0-9]+$")


@dataclass(slots=True, frozen=True)
class PipeElement:
    """One parsed ``|modifier``; ``arg`` carries the referenced field / threshold / CIDR / exists flag."""

    kind: Pipe
    arg: Any = None
    field: str = ""  # only for EXISTS: the field whose existence is tested

    @staticmethod
    def new(key: str, pattern: str, key_list: list[str]) -> PipeElement:
        """``PipeElement::new``. Raises ValueError with Hayabusa's error text on bad input."""
        if key in ("startswith", "endswith", "contains", "re", "reignorecase", "resingleline", "remultiline", "expand", "base64", "base64offset", "windash", "all", "allOnly", "cased", "utf16", "utf16le", "utf16be", "wide"):
            return PipeElement(Pipe(key))
        if key == "exists":
            return PipeElement(Pipe.EXISTS, pattern, key_list[0].split("|")[0])
        if key in ("equalsfield", "endswithfield", "fieldref", "fieldrefstartswith", "fieldrefendswith", "fieldrefcontains"):
            return PipeElement(Pipe(key), pattern)
        if key == "cidr":
            try:
                network = ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                network = None
            return PipeElement(Pipe.CIDR, network)
        if key in ("gt", "lt", "gte", "lte"):
            if not _USIZE_RE.match(pattern):
                raise ValueError(f"{key} value should be a number. key:{concat_selection_key(key_list)}")
            return PipeElement(Pipe(key), int(pattern))
        raise ValueError(f"An unknown pipe element was specified. key:{concat_selection_key(key_list)}")

    def get_eqfield(self) -> str | None:
        """``fieldref::get_key``: the other field an equalsfield/fieldref-style pipe refers to."""
        if self.kind in _FIELD_REF_PIPES:
            return self.arg
        return None

    def pipe_pattern(self, pattern: str) -> str:
        """``PipeElement::pipe_pattern``: apply this modifier's transformation to the pattern."""
        if self.kind in (Pipe.STARTSWITH, Pipe.ENDSWITH, Pipe.CONTAINS, Pipe.WILDCARD):
            return wrap_pattern(self.kind, pattern)
        if self.kind is Pipe.RE_IGNORE_CASE:
            return "(?i)" + pattern
        if self.kind is Pipe.RE_MULTI_LINE:
            return "(?m)" + pattern
        if self.kind is Pipe.RE_SINGLE_LINE:
            return "(?s)" + pattern
        return pattern

    def value_match(self, event_value: str | None, recinfo: RecordInfo) -> bool | None:
        """``modifiers::ValueMatcher``: Some(result) for cidr/exists/fieldref/numeric, else None."""
        kind = self.kind
        if kind is Pipe.CIDR:
            return _cidr_match(self.arg, event_value)
        if kind is Pipe.EXISTS or kind in _FIELD_REF_PIPES:
            return _fieldref_match(self, event_value, recinfo)
        if kind in _NUMERIC_PIPES:
            return _numeric_match(self, event_value)
        return None


def _cidr_match(network: Any, event_value: str | None) -> bool:
    if network is None:
        return False
    try:
        address = ipaddress.ip_address(event_value or "")
    except ValueError:
        return False
    try:
        return address in network
    except TypeError:
        return False


def _numeric_match(pipe: PipeElement, event_value: str | None) -> bool:
    text = event_value or ""
    if not _USIZE_RE.match(text):
        return False
    number = int(text)
    if pipe.kind is Pipe.GT:
        return number > pipe.arg
    if pipe.kind is Pipe.LT:
        return number < pipe.arg
    if pipe.kind is Pipe.GTE:
        return number >= pipe.arg
    if pipe.kind is Pipe.LTE:
        return number <= pipe.arg
    return False


def _fieldref_match(pipe: PipeElement, event_value: str | None, recinfo: RecordInfo) -> bool:
    kind = pipe.kind
    if kind is Pipe.EXISTS:
        expected = str(pipe.arg).lower()
        return expected == ("true" if recinfo.get_value(pipe.field) is not None else "false")
    other = recinfo.get_value(pipe.arg)
    if event_value is None or other is None:
        return False
    if kind in (Pipe.EQUALS_FIELD, Pipe.FIELD_REF):
        return other == event_value
    if kind is Pipe.FIELD_REF_STARTSWITH:
        return event_value.lower().startswith(other.lower())
    if kind in (Pipe.ENDSWITH_FIELD, Pipe.FIELD_REF_ENDSWITH):
        return event_value.lower().endswith(other.lower())
    if kind is Pipe.FIELD_REF_CONTAINS:
        return other.lower() in event_value.lower()
    return False


# --------------------------------------------------------------------------------------------
# String modifiers and wildcard conversion (modifiers/string.rs, modifiers/regex.rs)
# --------------------------------------------------------------------------------------------


def _add_asterisk_end(pattern: str) -> str:
    if pattern.endswith("//*"):
        return pattern
    if pattern.endswith("/*"):
        return pattern + "*"
    if pattern.endswith("*"):
        return pattern
    if pattern.endswith("\\"):
        # A trailing single backslash becomes "\\*": a literal backslash followed by the wildcard.
        return pattern + "\\*"
    return pattern + "*"


def _add_asterisk_begin(pattern: str) -> str:
    if pattern.startswith("//*"):
        return pattern
    if pattern.startswith("/*"):
        return "*" + pattern
    if pattern.startswith("*"):
        return pattern
    return "*" + pattern


def wrap_pattern(kind: Pipe, pattern: str) -> str:
    """``string::wrap_pattern``: add the surrounding wildcards for startswith/endswith/contains."""
    if kind is Pipe.STARTSWITH:
        return _add_asterisk_end(pattern)
    if kind is Pipe.ENDSWITH:
        return _add_asterisk_begin(pattern)
    if kind is Pipe.CONTAINS:
        return _add_asterisk_end(_add_asterisk_begin(pattern))
    if kind is Pipe.WILDCARD:
        return wildcard_to_regex(pattern)
    return pattern


_STAR_REGEX = r"(.|\a|\f|\t|\n|\r|\v)*"
_RUST_REGEX_META = set("\\.+*?()|[]{}^$#&-~")


def regex_escape(text: str) -> str:
    """Rust ``regex::escape``: backslash-escape exactly the regex meta characters (not spaces)."""
    return "".join("\\" + ch if ch in _RUST_REGEX_META else ch for ch in text)


def wildcard_to_regex(pattern: str) -> str:
    """``string::wildcard_to_regex``: Sigma ``*``/``?`` (with ``\\`` escaping) -> case-insensitive regex.

    Returns the same text the Rust code builds (``(?i)`` prefix, ``regex::escape``d literals);
    the caller compiles it with :func:`compile_regex`, which maps Rust regex syntax to Python's.
    """
    wildcards = ("*", "?")
    idx = 0
    splits: list[str] = []
    cur = ""
    length = len(pattern)
    while idx < length:
        prev_idx = idx
        rest = pattern[idx:]
        for wildcard in wildcards:
            if rest.startswith("\\\\" + wildcard):
                # Two escape characters before the wildcard: a literal backslash, then a wildcard.
                cur += "\\"
                splits.append(cur)
                splits.append(wildcard)
                cur = ""
                idx += 3
                break
            if rest.startswith("\\" + wildcard):
                # One escape character: the wildcard character itself, literally.
                cur += wildcard
                idx += 2
                break
            if rest.startswith(wildcard):
                splits.append(cur)
                splits.append(wildcard)
                cur = ""
                idx += 1
                break
        if prev_idx != idx:
            continue
        cur += pattern[idx]
        idx += 1
    if cur:
        splits.append(cur)
    out = ""
    for index, piece in enumerate(splits):
        if index % 2 == 0:
            out += regex_escape(piece)
        else:
            out += _STAR_REGEX if piece == "*" else "."
    return "(?i)" + out


_INLINE_FLAG_RE = re.compile(r"^\(\?([imsxu]+)\)")
_LEADING_FLAGS_RE = re.compile(r"^(?:\(\?[a-zA-Z]+\))+")


def compile_regex(pattern: str) -> re.Pattern[str]:
    """Compile a Rust-``regex``-syntax pattern with Python's ``re``.

    Differences handled: Python needs global inline flags at the very start (Rust allows them
    anywhere, and our own wrapping may put ``^(?:`` before a ``(?i)``), and Python's ``$`` also
    matches before a trailing newline whereas Rust's matches only at the end of text, so the
    full-value anchoring produced by ``DefaultMatcher`` uses ``\\A``/``\\Z``.
    """
    flags = 0
    # Hoist inline flags that appear right after our anchoring prefix "^(?:" or at the start.
    prefix = ""
    body = pattern
    if body.startswith("^(?:"):
        prefix = "^(?:"
        body = body[4:]
    match = _LEADING_FLAGS_RE.match(body)
    if match:
        for flag_group in re.findall(r"\(\?([a-zA-Z]+)\)", match.group(0)):
            for flag in flag_group:
                if flag == "i":
                    flags |= re.IGNORECASE
                elif flag == "m":
                    flags |= re.MULTILINE
                elif flag == "s":
                    flags |= re.DOTALL
                elif flag == "x":
                    flags |= re.VERBOSE
                elif flag == "u":
                    pass
                else:
                    raise re.error(f"unsupported inline flag {flag}")
        body = body[match.end() :]
    if prefix:
        # "^(?:...)$" -> "\A(?:...)\Z" so that "$" cannot match before a trailing newline.
        assert body.endswith(")$")
        body = "\\A(?:" + body[:-2] + ")\\Z"
    return re.compile(_scope_inline_flags(body), flags)


_MID_FLAG_RE = re.compile(r"\(\?([a-zA-Z]+(?:-[a-zA-Z]+)?|-[a-zA-Z]+)\)")


def _scope_inline_flags(pattern: str) -> str:
    """Rewrite Rust-style mid-pattern flag groups ``(?i)`` (which apply from that point to the
    end of the enclosing group) into Python's scoped form ``(?i:...)``.

    Python only accepts bare ``(?i)`` at the very start of a pattern. Escapes and character
    classes are skipped so a literal ``(`` never confuses the group tracking.
    """
    out: list[str] = []
    # Stack of open groups; each entry counts how many scoped-flag wrappers must be closed
    # when that group closes. The bottom entry is the whole pattern.
    pending = [0]
    i = 0
    n = len(pattern)
    in_class = False
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            out.append(pattern[i : i + 2])
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            out.append(ch)
            i += 1
            continue
        if ch == "[":
            in_class = True
            out.append(ch)
            i += 1
            # A "]" right after "[" or "[^" is a literal.
            if i < n and pattern[i] == "^":
                out.append("^")
                i += 1
            if i < n and pattern[i] == "]":
                out.append("]")
                i += 1
            continue
        if ch == "(":
            match = _MID_FLAG_RE.match(pattern, i)
            if match and i > 0:
                flags = match.group(1).replace("u", "")
                if flags in ("", "-"):
                    i = match.end()
                    continue
                out.append(f"(?{flags}:")
                pending[-1] += 1
                i = match.end()
                continue
            pending.append(0)
            out.append(ch)
            i += 1
            continue
        if ch == ")":
            closers = pending.pop() if len(pending) > 1 else 0
            out.append(")" * closers)
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    out.append(")" * pending[0])
    return "".join(out)


# --------------------------------------------------------------------------------------------
# Fast matching (fast_match.rs)
# --------------------------------------------------------------------------------------------


class FastKind(Enum):
    EXACT = "exact"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    CONTAINS = "contains"
    ALL_ONLY = "all_only"


@dataclass(slots=True, frozen=True)
class FastMatch:
    kind: FastKind
    text: str


def _is_literal_asterisk(pattern: str) -> bool:
    return pattern.endswith("\\*") and not pattern.endswith("\\\\*")


def convert_to_fast_match(pattern: str, ignore_case: bool) -> list[FastMatch] | None:
    """``fast_match::convert_to_fast_match``: wildcard pattern -> string-operation plan, or None
    when only the regex engine can handle it."""
    wildcard_count = pattern.count("*")
    if "?" in pattern or pattern.endswith("\\\\\\*") or (not pattern.isascii() and "*" in pattern):
        return None
    if pattern.startswith("allOnly*") and pattern.endswith("*") and wildcard_count == 2:
        text = pattern[8:-1].replace("\\\\", "\\")
        return [FastMatch(FastKind.ALL_ONLY, text.lower() if ignore_case else text)]
    if pattern.startswith("*") and pattern.endswith("*") and wildcard_count == 2 and not _is_literal_asterisk(pattern):
        text = pattern[1:-1].replace("\\\\", "\\")
        return [FastMatch(FastKind.CONTAINS, text.lower() if ignore_case else text)]
    if pattern.startswith("*") and wildcard_count == 1 and not _is_literal_asterisk(pattern):
        return [FastMatch(FastKind.ENDS_WITH, pattern[1:].replace("\\\\", "\\"))]
    if pattern.endswith("*") and wildcard_count == 1 and not _is_literal_asterisk(pattern):
        return [FastMatch(FastKind.STARTS_WITH, pattern[:-1].replace("\\\\", "\\"))]
    if "*" in pattern:
        return None
    return [FastMatch(FastKind.EXACT, pattern.replace("\\\\", "\\"))]


def _replace_first_windash(text: str, windash_chars: tuple[str, ...]) -> str:
    """Rust ``str::replacen(&[char], "/", 1)``: replace the first occurrence of any dash character."""
    for index, ch in enumerate(text):
        if ch in windash_chars:
            return text[:index] + "/" + text[index + 1 :]
    return text


def check_fast_match(pipes: list[PipeElement], event_value: str, fast_matcher: list[FastMatch], windash_chars: tuple[str, ...]) -> bool | None:
    """``fast_match::check_fast_match``."""
    kinds = {pipe.kind for pipe in pipes}
    if len(fast_matcher) == 1:
        fm = fast_matcher[0]
        if fm.kind is FastKind.EXACT:
            return eq_ignore_case(event_value, fm.text)
        if fm.kind is FastKind.STARTS_WITH:
            if Pipe.CASED in kinds:
                return event_value.startswith(fm.text)
            return starts_with_ignore_case(event_value, fm.text)
        if fm.kind is FastKind.ENDS_WITH:
            if Pipe.CASED in kinds:
                return event_value.endswith(fm.text)
            return ends_with_ignore_case(event_value, fm.text)
        # CONTAINS / ALL_ONLY
        if Pipe.WINDASH in kinds:
            return fm.text in _replace_first_windash(event_value, windash_chars).lower()
        if Pipe.CASED in kinds:
            return fm.text in event_value
        return fm.text in event_value.lower()
    windash = Pipe.WINDASH in kinds
    for fm in fast_matcher:
        if fm.kind is not FastKind.CONTAINS:
            continue
        if windash:
            if fm.text in _replace_first_windash(event_value, windash_chars).lower():
                return True
        elif fm.text in event_value:
            return True
    return False


# --------------------------------------------------------------------------------------------
# base64 / UTF-16 encodings (base64_match.rs, modifiers/encoding.rs)
# --------------------------------------------------------------------------------------------


def to_base64_utf8(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def to_base64_utf16le_with_bom(text: str, with_bom: bool) -> str:
    data = (b"\xff\xfe" if with_bom else b"") + text.encode("utf-16-le")
    return base64.b64encode(data).decode("ascii").rstrip("=")


def to_base64_utf16be(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-be")).decode("ascii").rstrip("=")


def _make_base64_str(encode: Pipe | None, original: str, variant_index: int) -> str:
    target = b"\x00" * variant_index
    if encode is Pipe.UTF16BE:
        target += original.encode("utf-16-be")
    elif encode in (Pipe.UTF16LE, Pipe.WIDE):
        target += original.encode("utf-16-le")
    else:
        target += original.encode("utf-8")
    return base64.b64encode(target).decode("ascii")


def _base64_offset(offset: int, b64: str) -> str:
    """``base64_match::base64_offset``: drop the characters not fully determined by the value."""
    pad_index = b64.find("=")
    remainder = (pad_index if pad_index >= 0 else 0) % 4
    if remainder == 2:
        return b64[: len(b64) - 3] if offset == 0 else b64[offset + 1 : len(b64) - 3]
    if remainder == 3:
        return b64[: len(b64) - 2] if offset == 0 else b64[offset + 1 : len(b64) - 2]
    return b64 if offset == 0 else b64[offset + 1 :]


def convert_to_base64_str(encode: Pipe | None, original: str) -> list[FastMatch] | None:
    """``base64_match::convert_to_base64_str``: the three byte-alignment variants as Contains matches."""
    fastmatches: list[FastMatch] = []
    for offset in range(3):
        b64 = _make_base64_str(encode, original, offset)
        contents = _base64_offset(offset, b64)
        converted = convert_to_fast_match(f"*{contents}*", False)
        if converted:
            fastmatches.extend(converted)
    return fastmatches or None


class _Encoding(Enum):
    PLAIN = 0
    BASE64 = 1
    BASE64_OFFSET = 2


class _Utf16(Enum):
    NONE = 0
    UTF16 = 1
    UTF16LE = 2
    UTF16BE = 3
    WIDE = 4


def _base64_encoded(utf16: _Utf16, original: str) -> str:
    if utf16 is _Utf16.NONE:
        return to_base64_utf8(original)
    if utf16 is _Utf16.UTF16:
        return to_base64_utf16le_with_bom(original, True)
    if utf16 in (_Utf16.UTF16LE, _Utf16.WIDE):
        return to_base64_utf16le_with_bom(original, False)
    return to_base64_utf16be(original)


def _base64offset_fast_match(utf16: _Utf16, original: str) -> list[FastMatch] | None:
    if utf16 is _Utf16.NONE:
        return convert_to_base64_str(None, original)
    if utf16 is _Utf16.UTF16:
        le = convert_to_base64_str(Pipe.UTF16LE, original)
        be = convert_to_base64_str(Pipe.UTF16BE, original)
        if le is None or be is None:
            return None
        return le + be
    if utf16 is _Utf16.UTF16LE:
        return convert_to_base64_str(Pipe.UTF16LE, original)
    if utf16 is _Utf16.UTF16BE:
        return convert_to_base64_str(Pipe.UTF16BE, original)
    return convert_to_base64_str(Pipe.WIDE, original)


class _Wrap(Enum):
    NONE = 0
    STARTS_WITH = 1
    ENDS_WITH = 2
    CONTAINS = 3
    ALL_ONLY = 4


@dataclass(slots=True)
class _MatchPlan:
    """``default_matcher::MatchPlan``: the fast-path modifiers folded into canonical fields."""

    wrap: _Wrap = _Wrap.NONE
    encoding: _Encoding = _Encoding.PLAIN
    utf16: _Utf16 = _Utf16.NONE
    cased: bool = False
    windash: bool = False
    all: bool = False

    @classmethod
    def from_pipes(cls, pipes: list[PipeElement]) -> _MatchPlan | None:
        plan = cls()
        for pipe in pipes:
            kind = pipe.kind
            if kind is Pipe.STARTSWITH:
                plan.wrap = _Wrap.STARTS_WITH
            elif kind is Pipe.ENDSWITH:
                plan.wrap = _Wrap.ENDS_WITH
            elif kind is Pipe.CONTAINS:
                plan.wrap = _Wrap.CONTAINS
            elif kind is Pipe.ALL_ONLY:
                plan.wrap = _Wrap.ALL_ONLY
            elif kind is Pipe.BASE64:
                plan.encoding = _Encoding.BASE64
            elif kind is Pipe.BASE64_OFFSET:
                plan.encoding = _Encoding.BASE64_OFFSET
            elif kind is Pipe.UTF16:
                plan.utf16 = _Utf16.UTF16
            elif kind is Pipe.UTF16LE:
                plan.utf16 = _Utf16.UTF16LE
            elif kind is Pipe.UTF16BE:
                plan.utf16 = _Utf16.UTF16BE
            elif kind is Pipe.WIDE:
                plan.utf16 = _Utf16.WIDE
            elif kind is Pipe.CASED:
                plan.cased = True
            elif kind is Pipe.WINDASH:
                plan.windash = True
            elif kind is Pipe.ALL:
                plan.all = True
            else:
                return None
        return plan

    def build_fast_match(self, pattern: list[str], windash_chars: tuple[str, ...]) -> list[FastMatch] | None:
        if self.encoding is _Encoding.PLAIN:
            if self.utf16 is not _Utf16.NONE:
                return None
            wrap = self.wrap
            if wrap is _Wrap.NONE:
                if self.cased or self.windash or self.all:
                    return None
                return convert_to_fast_match(pattern[0], True)
            if wrap in (_Wrap.STARTS_WITH, _Wrap.ENDS_WITH):
                if self.windash or self.all:
                    return None
                wrapped = f"{pattern[0]}*" if wrap is _Wrap.STARTS_WITH else f"*{pattern[0]}"
                return convert_to_fast_match(wrapped, not self.cased)
            if wrap is _Wrap.ALL_ONLY:
                if self.cased or self.windash or self.all:
                    return None
                return convert_to_fast_match(f"allOnly*{pattern[0]}*", True)
            if self.windash:  # CONTAINS + windash
                if self.cased:
                    return None
                if self.all:
                    pattern.append(_replace_first_windash(pattern[0], windash_chars))
                fastmatches = convert_to_fast_match(f"*{pattern[0]}*", True) or []
                fastmatches.extend(convert_to_fast_match(f"*{_replace_first_windash(pattern[0], windash_chars)}*", True) or [])
                return fastmatches or None
            # plain CONTAINS
            if self.all and self.cased:
                return None
            return convert_to_fast_match(f"*{pattern[0]}*", not self.cased)
        if self.encoding is _Encoding.BASE64:
            if self.wrap is not _Wrap.CONTAINS or self.cased or self.windash or self.all:
                return None
            return convert_to_fast_match(f"*{_base64_encoded(self.utf16, pattern[0])}*", True)
        # BASE64_OFFSET
        if self.wrap is not _Wrap.CONTAINS or self.cased or self.windash or self.all:
            return None
        return _base64offset_fast_match(self.utf16, pattern[0])


# --------------------------------------------------------------------------------------------
# Leaf matchers
# --------------------------------------------------------------------------------------------


@dataclass(slots=True)
class MatcherContext:
    """Static configuration the matchers need (``WINDASH_CHARACTERS`` and the base directory
    that ``regexes:``/``allowlist:`` file references are resolved against)."""

    windash_chars: tuple[str, ...] = ("-", "–", "—", "―")
    base_dir: Path | None = None

    def resolve(self, filename: str) -> Path:
        path = Path(filename)
        if not path.is_absolute() and self.base_dir is not None:
            candidate = self.base_dir / filename
            if candidate.exists():
                return candidate
        return path


DEFAULT_CONTEXT = MatcherContext()


class LeafMatcher:
    """``matchers::LeafMatcher`` trait."""

    def is_target_key(self, key_list: list[str]) -> bool:
        raise NotImplementedError

    def init(self, key_list: list[str], select_value: Any, ctx: MatcherContext) -> list[str]:
        """Returns a list of error messages (empty on success)."""
        raise NotImplementedError

    def is_match(self, event_value: str | None, recinfo: RecordInfo) -> bool:
        raise NotImplementedError

    def is_negated(self) -> bool:
        return False


class MinlengthMatcher(LeafMatcher):
    """``field: {min_length: N}``: the value has at least N bytes."""

    __slots__ = ("min_len",)

    def __init__(self) -> None:
        self.min_len = 0

    def is_target_key(self, key_list: list[str]) -> bool:
        return len(key_list) == 2 and key_list[1] == "min_length"

    def init(self, key_list: list[str], select_value: Any, ctx: MatcherContext) -> list[str]:
        min_length = as_i64(select_value)
        if min_length is None:
            return [f"min_length value should be an integer. [key:{concat_selection_key(key_list)}]"]
        self.min_len = min_length
        return []

    def is_match(self, event_value: str | None, recinfo: RecordInfo) -> bool:
        if event_value is None:
            return False
        return _byte_len(event_value) >= self.min_len


def _read_regex_file(filename: str, ctx: MatcherContext) -> list[re.Pattern[str]] | str:
    path = ctx.resolve(filename)
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\r\n") for line in handle]
    except OSError:
        return f"Cannot open file. [file:{filename}]"
    return [compile_regex(line) for line in lines]


class RegexesFileMatcher(LeafMatcher):
    """``field: {regexes: file}``: the value matches any regex listed in ``file``."""

    __slots__ = ("regexes",)

    def __init__(self) -> None:
        self.regexes: list[re.Pattern[str]] = []

    def is_target_key(self, key_list: list[str]) -> bool:
        return len(key_list) == 2 and key_list[1] == "regexes"

    def init(self, key_list: list[str], select_value: Any, ctx: MatcherContext) -> list[str]:
        # Yaml::as_str() only succeeds for genuine strings (Integer/Real give None here).
        value = select_value if isinstance(select_value, str) and not isinstance(select_value, YamlReal) else None
        if value is None:
            return [f"regexes value should be a string. [key:{concat_selection_key(key_list)}]"]
        loaded = _read_regex_file(value, ctx)
        if isinstance(loaded, str):
            return [loaded]
        self.regexes = loaded
        return []

    def is_match(self, event_value: str | None, recinfo: RecordInfo) -> bool:
        if event_value is None:
            return False
        return any(regex.search(event_value) for regex in self.regexes)


class AllowlistFileMatcher(LeafMatcher):
    """``field: {allowlist: file}``: matches unless the value matches a regex listed in ``file``."""

    __slots__ = ("regexes",)

    def __init__(self) -> None:
        self.regexes: list[re.Pattern[str]] = []

    def is_target_key(self, key_list: list[str]) -> bool:
        return len(key_list) == 2 and key_list[1] == "allowlist"

    def init(self, key_list: list[str], select_value: Any, ctx: MatcherContext) -> list[str]:
        if isinstance(select_value, bool) or not isinstance(select_value, (str, int)):
            return [f"allowlist value should be a string. [key:{concat_selection_key(key_list)}]"]
        loaded = _read_regex_file(str(select_value), ctx)
        if isinstance(loaded, str):
            return [loaded]
        self.regexes = loaded
        return []

    def is_match(self, event_value: str | None, recinfo: RecordInfo) -> bool:
        if event_value is None:
            return True
        return not any(regex.search(event_value) for regex in self.regexes)


_CHANGE_MAP = {"all": "allOnly", "i": "reignorecase", "m": "remultiline", "s": "resingleline"}


class DefaultMatcher(LeafMatcher):
    """``DefaultMatcher``: wildcards, pipes, fast matches and the regex fallback."""

    __slots__ = ("fast_match", "key_list", "neg_match", "pipes", "re", "windash_chars")

    def __init__(self) -> None:
        self.re: list[re.Pattern[str]] | None = None
        self.fast_match: list[FastMatch] | None = None
        self.pipes: list[PipeElement] = []
        self.key_list: list[str] = []
        self.neg_match = False
        self.windash_chars: tuple[str, ...] = DEFAULT_CONTEXT.windash_chars

    def get_eqfield_key(self) -> str | None:
        if not self.pipes:
            return None
        return self.pipes[0].get_eqfield()

    def is_target_key(self, key_list: list[str]) -> bool:
        if len(key_list) <= 1:
            return True
        return key_list[1] == "value"

    def init(self, key_list: list[str], select_value: Any, ctx: MatcherContext) -> list[str]:
        self.key_list = list(key_list)
        self.windash_chars = ctx.windash_chars
        if select_value is None:
            return []
        yaml_value = scalar_to_pattern(select_value)
        if yaml_value is None:
            return [f"An unknown error occured. [key:{concat_selection_key(key_list)}]"]
        pattern = [yaml_value]
        keys_all = (key_list[0] if key_list else "").split("|")

        # `neq` negates the whole comparison; strip it from the modifier chain.
        if len(keys_all) >= 2 and "neq" in keys_all[1:]:
            self.neg_match = True
            keys_all = [keys_all[0]] + [key for key in keys_all[1:] if key != "neq"]
        if self.neg_match and keys_all[0] == "":
            return ["The `neq` modifier cannot be combined with the keyless `|all` modifier."]

        if keys_all[0] == "" and len(keys_all) == 2 and keys_all[1] == "all":
            keys_all[1] = _CHANGE_MAP["all"]
        if len(keys_all) >= 3:
            if keys_all[1] == "re":
                if keys_all[2] in ("i", "m", "s"):
                    keys_all[2] = _CHANGE_MAP[keys_all[2]]
                del keys_all[1]
            elif keys_all[1] == "fieldref" and keys_all[2] == "endswith":
                keys_all[1] = "fieldrefendswith"
                del keys_all[2]
            elif keys_all[1] == "fieldref" and keys_all[2] == "startswith":
                keys_all[1] = "fieldrefstartswith"
                del keys_all[2]
            elif keys_all[1] == "fieldref" and keys_all[2] == "contains":
                keys_all[1] = "fieldrefcontains"
                del keys_all[2]

        errors: list[str] = []
        for key in keys_all[1:]:
            try:
                self.pipes.append(PipeElement.new(key, pattern[0], key_list))
            except ValueError as error:
                errors.append(str(error))
        if errors:
            return errors
        if len(self.pipes) >= 4:
            return [f"Multiple pipe elements cannot be used. key:{concat_selection_key(key_list)}"]

        plan = _MatchPlan.from_pipes(self.pipes)
        self.fast_match = plan.build_fast_match(pattern, self.windash_chars) if plan is not None else None
        if self.fast_match and self.fast_match[0].kind in (FastKind.EXACT, FastKind.CONTAINS) and self.key_list:
            # Fully handled by string operations; no regex needed.
            return []

        is_eqfield = any(pipe.kind in _FIELD_REF_PIPES for pipe in self.pipes)
        if is_eqfield:
            return []
        is_re = any(pipe.kind in _REGEX_PIPES for pipe in self.pipes)
        if not is_re:
            self.pipes.append(PipeElement(Pipe.WILDCARD))
        is_whole_record_search = not self.key_list or self.key_list[0] == "|all"
        compiled: list[re.Pattern[str]] = []
        for pattern_str in pattern:
            regex_str = pattern_str
            for pipe in self.pipes:
                regex_str = pipe.pipe_pattern(regex_str)
            if not is_re and not is_whole_record_search:
                regex_str = f"^(?:{regex_str})$"
            try:
                compiled.append(compile_regex(regex_str))
            except (re.error, AssertionError, OverflowError):
                return [f"Cannot parse regex. [regex:{regex_str}, key:{concat_selection_key(key_list)}]"]
        self.re = compiled
        return []

    def is_match(self, event_value: str | None, recinfo: RecordInfo) -> bool:
        return self._is_match_inner(event_value, recinfo) ^ self.neg_match

    def is_negated(self) -> bool:
        return self.neg_match

    def _is_match_inner(self, event_value: str | None, recinfo: RecordInfo) -> bool:
        if self.pipes:
            result = self.pipes[0].value_match(event_value, recinfo)
            if result is not None:
                return result
        if not self.key_list and self.re is None and self.fast_match is None:
            return False
        if self.re is None and self.fast_match is None:
            # A null rule value matches when the field is absent from the record.
            for key in self.key_list:
                if recinfo.get_value(key) is None:
                    return True
            return False
        if event_value is None:
            return False
        if not self.key_list:
            return any(regex.search(event_value) for regex in self.re or [])
        if self.fast_match is not None:
            result = check_fast_match(self.pipes, event_value, self.fast_match, self.windash_chars)
            if result is not None:
                return result
        if self.re is None:
            return False
        return any(regex.search(event_value) for regex in self.re)


def get_matchers() -> list[LeafMatcher]:
    """``LeafSelectionNode::get_matchers``: examined in order; DefaultMatcher must stay last."""
    return [MinlengthMatcher(), RegexesFileMatcher(), AllowlistFileMatcher(), DefaultMatcher()]
