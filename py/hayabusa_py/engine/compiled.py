"""Compile a selection tree into nested closures.

The tree-walking ``select`` methods reproduce the Rust structure one node at a time; on records
with ~1,000 candidate rules (Sysmon process creation) that is ~9,000 leaf evaluations per
event, each several Python call layers deep. ``compile_node`` produces one closure per node with
the common leaf shapes specialised — plain key with a single fast match, plain-integer
``EventID``, ``cidr``, wildcard patterns that are really contains/startswith/endswith tests,
and OR lists of such leaves on one key — and everything else delegating to the node's own
``select``. The specialisations reproduce the exact comparisons of
:mod:`hayabusa_py.engine.selection` / :mod:`hayabusa_py.engine.matchers` (ASCII case folding
for fast matches, ``str.lower`` for wildcard patterns), so results are identical.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from hayabusa_py.engine.matchers import (
    _ASCII_LOWER,
    _FIELD_REF_PIPES,
    _NUMERIC_PIPES,
    QMARK,
    DefaultMatcher,
    FastKind,
    Pipe,
    WildcardPattern,
    _byte_len,
    _cidr_match,
    _wildcard_match,
)
from hayabusa_py.engine.selection import (
    LeafSelectionNode,
    NarySelectionNode,
    NotSelectionNode,
    RefSelectionNode,
    SelectionNode,
)
from hayabusa_py.evtx.record import RecordInfo
from hayabusa_py.rules.config import EventKeyAlias
from hayabusa_py.rules.yaml12 import as_i64

Predicate = Callable[[RecordInfo], bool]

_NO_ALIAS = EventKeyAlias()
_EXCLUDED_PIPES = {Pipe.CASED, Pipe.WINDASH, Pipe.ALL_ONLY, Pipe.EXISTS} | _NUMERIC_PIPES | _FIELD_REF_PIPES
_SPECIAL_KEYS = {"EventData", "Data", ""}


@dataclass(slots=True, frozen=True)
class Simple:
    """A leaf reduced to ``mode`` applied to ``record.get_value(key)``.

    modes: exact/contains/starts/ends (fast match, ASCII folding), wcontains/wstarts/wends
    (wildcard pattern, ``str.lower`` folding), eid (plain-integer EventID), cidr.
    """

    key: str
    mode: str
    needle: Any
    fallback: Any = None  # starts/ends: the matcher's regex list for non-ASCII values


def _simple_leaf(node: LeafSelectionNode) -> Simple | None:
    matcher = node.matcher
    if not isinstance(matcher, DefaultMatcher) or matcher.neg_match:
        return None
    if len(node.key_list) != 1 or node.key_list[0] == "|all":
        return None
    key = node.key
    if key in _SPECIAL_KEYS:
        return None
    if key == "EventID":
        if "|" in node.key_list[0] or node.select_value is None:
            return None
        number = as_i64(node.select_value)
        return Simple(key, "eid", str(number)) if number is not None else None
    kinds = {pipe.kind for pipe in matcher.pipes}
    if kinds & _EXCLUDED_PIPES:
        return None
    if Pipe.CIDR in kinds:
        if matcher.pipes[0].kind is not Pipe.CIDR:
            return None
        return Simple(key, "cidr", matcher.pipes[0].arg)
    if kinds & {Pipe.RE, Pipe.RE_IGNORE_CASE, Pipe.RE_MULTI_LINE, Pipe.RE_SINGLE_LINE}:
        return None
    fast = matcher.fast_match
    if fast is not None:
        if len(fast) != 1 or fast[0].kind is FastKind.ALL_ONLY:
            return None
        fm = fast[0]
        if fm.kind is FastKind.EXACT:
            return Simple(key, "exact", fm.text)
        if fm.kind is FastKind.CONTAINS:
            return Simple(key, "contains", fm.text)
        mode = "starts" if fm.kind is FastKind.STARTS_WITH else "ends"
        return Simple(key, mode, fm.text, matcher.re)
    # No fast match: a wildcard pattern. Recognise the shapes that are plain string tests.
    if matcher.re is None or len(matcher.re) != 1 or not isinstance(matcher.re[0], WildcardPattern):
        return None
    wildcard = matcher.re[0]
    if not wildcard.anchored:
        return None
    segments = wildcard.segments
    if any(QMARK in seg for seg in segments):
        return Simple(key, "wild", wildcard)
    if len(segments) == 3 and not segments[0] and not segments[-1]:
        return Simple(key, "wcontains", "".join(segments[1]))
    if len(segments) == 2 and not segments[0]:
        return Simple(key, "wends", "".join(segments[1]))
    if len(segments) == 2 and not segments[1]:
        return Simple(key, "wstarts", "".join(segments[0]))
    return Simple(key, "wild", wildcard)


def node_select(node: SelectionNode) -> Predicate:
    """Generic fallback: the node's own tree-walking ``select``."""

    def run(record: RecordInfo) -> bool:
        return node.select(record, record.alias or _NO_ALIAS)

    return run


def _ascii_affix(record: RecordInfo, key: str, blen: int, lowered: str, fallback: Any, at_end: bool) -> bool:
    value = record.get_value(key)
    if value is None:
        return False
    if value.isascii():
        if len(value) < blen:
            return False
        piece = value[len(value) - blen :] if at_end else value[:blen]
        return piece.translate(_ASCII_LOWER) == lowered
    if blen > _byte_len(value):
        return False
    return bool(fallback) and any(regex.search(value) for regex in fallback)


def _compile_simple(simple: Simple) -> Predicate:
    key, mode, needle = simple.key, simple.mode, simple.needle
    if mode == "eid":
        return lambda record: (record.get_value(key) or "") == needle
    if mode == "cidr":
        return lambda record: _cidr_match(needle, record.get_value(key))
    if mode == "exact":
        lowered = needle.translate(_ASCII_LOWER)

        def exact(record: RecordInfo) -> bool:
            value = record.get_value(key)
            return value is not None and value.translate(_ASCII_LOWER) == lowered

        return exact
    if mode == "contains" or mode == "wcontains":
        def contains(record: RecordInfo) -> bool:
            return record.get_value(key) is not None and needle in record.lower_value(key)

        return contains
    if mode == "wstarts":
        return lambda record: record.get_value(key) is not None and record.lower_value(key).startswith(needle)
    if mode == "wends":
        return lambda record: record.get_value(key) is not None and record.lower_value(key).endswith(needle)
    if mode == "wild":
        segments = needle.segments
        anchored = needle.anchored
        return lambda record: record.get_value(key) is not None and _wildcard_match(segments, record.lower_value(key), anchored)
    lowered = needle.translate(_ASCII_LOWER)
    blen = _byte_len(needle)
    fallback = simple.fallback
    at_end = mode == "ends"
    return lambda record: _ascii_affix(record, key, blen, lowered, fallback, at_end)


def _compile_leaf(node: LeafSelectionNode) -> Predicate:
    simple = _simple_leaf(node)
    if simple is None:
        return node_select(node)
    return _compile_simple(simple)


def _compile_or_list(children: list[LeafSelectionNode]) -> Predicate | None:
    """An OR over leaves that all apply the same mode to the same key."""
    simples = [_simple_leaf(child) for child in children]
    if any(s is None for s in simples):
        return None
    key, mode = simples[0].key, simples[0].mode
    if any(s.key != key or s.mode != mode for s in simples):
        return None
    needles = tuple(s.needle for s in simples)
    if mode == "eid":
        wanted = set(needles)
        return lambda record: (record.get_value(key) or "") in wanted
    if mode == "exact":
        lowered = {needle.translate(_ASCII_LOWER) for needle in needles}

        def any_exact(record: RecordInfo) -> bool:
            value = record.get_value(key)
            return value is not None and value.translate(_ASCII_LOWER) in lowered

        return any_exact
    if mode in ("contains", "wcontains"):
        def any_contains(record: RecordInfo) -> bool:
            if record.get_value(key) is None:
                return False
            lower = record.lower_value(key)
            for needle in needles:
                if needle in lower:
                    return True
            return False

        return any_contains
    if mode == "wstarts":
        return lambda record: record.get_value(key) is not None and record.lower_value(key).startswith(needles)
    if mode == "wends":
        return lambda record: record.get_value(key) is not None and record.lower_value(key).endswith(needles)
    if mode in ("starts", "ends"):
        per_leaf = [_compile_simple(s) for s in simples]
        lowered_needles = tuple(needle.translate(_ASCII_LOWER) for needle in needles)
        at_end = mode == "ends"

        def any_affix(record: RecordInfo) -> bool:
            value = record.get_value(key)
            if value is None:
                return False
            if value.isascii():
                lower = value.translate(_ASCII_LOWER)
                return lower.endswith(lowered_needles) if at_end else lower.startswith(lowered_needles)
            for pred in per_leaf:
                if pred(record):
                    return True
            return False

        return any_affix
    return None


def compile_node(node: SelectionNode) -> Predicate:
    if isinstance(node, LeafSelectionNode):
        return _compile_leaf(node)
    if isinstance(node, RefSelectionNode):
        return compile_node(node.selection_node)
    if isinstance(node, NotSelectionNode):
        inner = compile_node(node.node)
        return lambda record: not inner(record)
    if isinstance(node, NarySelectionNode):
        children = node.child_nodes
        if not node.all_of and children and all(isinstance(child, LeafSelectionNode) for child in children):
            merged = _compile_or_list(children)  # type: ignore[arg-type]
            if merged is not None:
                return merged
        preds = [compile_node(child) for child in children]
        if len(preds) == 1:
            return preds[0]
        if node.all_of:
            def all_of(record: RecordInfo) -> bool:
                for pred in preds:
                    if not pred(record):
                        return False
                return True

            return all_of

        def any_of(record: RecordInfo) -> bool:
            for pred in preds:
                if pred(record):
                    return True
            return False

        return any_of
    return node_select(node)
