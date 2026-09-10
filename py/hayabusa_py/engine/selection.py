"""Selection tree nodes (port of ``src/detections/rule/selectionnodes.rs`` and the
``parse_selection_recursively`` logic of ``rulenode.rs``).

A named selection under ``detection`` compiles into a tree: YAML hashes become AND nodes, arrays
become OR nodes (AND nodes when the key carries ``|all``), scalars become leaves that delegate the
actual comparison to a :class:`~hayabusa_py.engine.matchers.LeafMatcher`.
"""

from __future__ import annotations

from typing import Any

from hayabusa_py.engine.matchers import (
    DefaultMatcher,
    LeafMatcher,
    MatcherContext,
    concat_selection_key,
    get_matchers,
)
from hayabusa_py.engine.values import get_event_value, value_to_string
from hayabusa_py.evtx.record import RecordInfo
from hayabusa_py.rules.config import EventKeyAlias
from hayabusa_py.rules.yaml12 import as_i64


class SelectionNode:
    """``SelectionNode`` trait."""

    __slots__ = ()

    def select(self, record: RecordInfo, alias: EventKeyAlias) -> bool:
        raise NotImplementedError

    def init(self, ctx: MatcherContext) -> list[str]:
        raise NotImplementedError

    def get_children(self) -> list[SelectionNode]:
        return []

    def get_descendants(self) -> list[SelectionNode]:
        result = list(self.get_children())
        for child in self.get_children():
            result.extend(child.get_descendants())
        return result


class NarySelectionNode(SelectionNode):
    """AND (``all_of=True``) or OR (``all_of=False``) over its children."""

    __slots__ = ("all_of", "child_nodes")

    def __init__(self, all_of: bool, child_nodes: list[SelectionNode] | None = None) -> None:
        self.all_of = all_of
        self.child_nodes: list[SelectionNode] = child_nodes if child_nodes is not None else []

    @classmethod
    def and_(cls) -> NarySelectionNode:
        return cls(True)

    @classmethod
    def or_(cls) -> NarySelectionNode:
        return cls(False)

    def select(self, record: RecordInfo, alias: EventKeyAlias) -> bool:
        if self.all_of:
            return all(child.select(record, alias) for child in self.child_nodes)
        return any(child.select(record, alias) for child in self.child_nodes)

    def init(self, ctx: MatcherContext) -> list[str]:
        errors: list[str] = []
        for child in self.child_nodes:
            errors.extend(child.init(ctx))
        return errors

    def get_children(self) -> list[SelectionNode]:
        return list(self.child_nodes)


class NotSelectionNode(SelectionNode):
    __slots__ = ("node",)

    def __init__(self, node: SelectionNode) -> None:
        self.node = node

    def select(self, record: RecordInfo, alias: EventKeyAlias) -> bool:
        return not self.node.select(record, alias)

    def init(self, ctx: MatcherContext) -> list[str]:
        return []


class RefSelectionNode(SelectionNode):
    """A reference from the condition expression to a named selection."""

    __slots__ = ("selection_node",)

    def __init__(self, selection_node: SelectionNode) -> None:
        self.selection_node = selection_node

    def select(self, record: RecordInfo, alias: EventKeyAlias) -> bool:
        return self.selection_node.select(record, alias)

    def init(self, ctx: MatcherContext) -> list[str]:
        return []

    def get_children(self) -> list[SelectionNode]:
        return [self.selection_node]

    def get_descendants(self) -> list[SelectionNode]:
        return self.get_children()


class LeafSelectionNode(SelectionNode):
    """One ``field|modifiers: value`` pair."""

    __slots__ = ("key", "key_list", "matcher", "select_value")

    def __init__(self, key_list: list[str], select_value: Any) -> None:
        self.key = ""
        self.key_list = list(key_list)
        self.select_value = select_value
        self.matcher: LeafMatcher | None = None

    def get_key(self) -> str:
        return self.key

    def get_keys(self) -> list[str]:
        """The record keys this leaf needs pre-extracted (its own field plus any referenced field)."""
        keys: list[str] = []
        if self.key:
            keys.append(self.key)
        if isinstance(self.matcher, DefaultMatcher):
            eq_key = self.matcher.get_eqfield_key()
            if eq_key is not None:
                keys.append(eq_key)
        return keys

    def _create_key(self) -> str:
        if not self.key_list:
            return ""
        return self.key_list[0].split("|", 1)[0]

    def _get_event_value(self, record: RecordInfo) -> str | None:
        if not self.key_list:
            # Keyword-style rule: match against the whole record text.
            return record.data_string
        return record.get_value(self.key)

    def select(self, record: RecordInfo, alias: EventKeyAlias) -> bool:
        matcher = self.matcher
        if matcher is None:
            return False
        key = self.key
        if key in ("EventData", "Data"):
            # EventData.Data may be an array of unnamed <Data> elements: match any element (all
            # elements for a negated matcher).
            values = get_event_value("Event.EventData.Data", record.record, alias)
            if values is None:
                return matcher.is_match(None, record)
            if isinstance(values, (bool, int, float, str)):
                return matcher.is_match(record.get_value(key), record)
            if isinstance(values, list):
                if matcher.is_negated():
                    return all(matcher.is_match(value_to_string(element), record) for element in values)
                return any(matcher.is_match(value_to_string(element), record) for element in values)
            return matcher.is_match(None, record)

        event_value = self._get_event_value(record)
        if key == "EventID" and self.select_value is not None and self.key_list and "|" not in self.key_list[0]:
            event_id = as_i64(self.select_value)
            if event_id is not None:
                # Plain integer EventID: exact string comparison instead of a regex.
                return (event_value or "") == str(event_id)
        if self.key_list and self.key_list[0] == "|all":
            event_value = record.data_string
        return matcher.is_match(event_value, record)

    def init(self, ctx: MatcherContext) -> list[str]:
        for candidate in get_matchers():
            if candidate.is_target_key(self.key_list):
                self.matcher = candidate
                break
        if self.matcher is None:
            return [f"Found unknown key. key:{concat_selection_key(self.key_list)}"]
        self.key = self._create_key()
        return self.matcher.init(self.key_list, self.select_value, ctx)


def _has_modifier(key_list: list[str], modifier: str) -> bool:
    return any(modifier in key.split("|")[1:] for key in key_list)


def parse_selection_recursively(key_list: list[str], value: Any) -> SelectionNode:
    """``DetectionNode::parse_selection_recursively``."""
    if isinstance(value, dict):
        node = NarySelectionNode.and_()
        for hash_key, child in value.items():
            child_key_list = key_list + [str(hash_key)]
            node.child_nodes.append(parse_selection_recursively(child_key_list, child))
        return node
    if isinstance(value, list):
        if len(key_list) == 1 and key_list[0] == "|all":
            # Keyless |all: every keyword must appear in the record.
            return NarySelectionNode(True, [parse_selection_recursively(key_list, child) for child in value])
        if any("|all" in key for key in key_list):
            children = [parse_selection_recursively(key_list, child) for child in value]
            # field|contains|all: AND of the values; with neq, De Morgan turns it into an OR.
            return NarySelectionNode(not _has_modifier(key_list, "neq"), children)
        if _has_modifier(key_list, "neq"):
            # neq over a list means "different from all of them": AND of the negated leaves.
            return NarySelectionNode(True, [parse_selection_recursively(key_list, child) for child in value])
        return NarySelectionNode(False, [parse_selection_recursively(key_list, child) for child in value])
    return LeafSelectionNode(key_list, value)
