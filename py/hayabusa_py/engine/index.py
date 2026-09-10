"""Candidate-rule index: skip rules that cannot match a record.

Hayabusa evaluates every loaded rule against every record. This index is the Python engine's
performance addition and is semantically conservative: a rule is bucketed by a ``Channel``
and/or ``EventID`` value only when its condition *requires* an exact (unmodified, wildcard-free)
match on that field, so the candidate set is always a superset of the rules that could match.

Required leaves are computed over the compiled condition tree: an AND node requires the union
of its children's requirements, an OR node the intersection, ``not`` requires nothing.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from hayabusa_py.engine.rule import RuleNode
from hayabusa_py.engine.selection import (
    LeafSelectionNode,
    NarySelectionNode,
    NotSelectionNode,
    RefSelectionNode,
    SelectionNode,
)
from hayabusa_py.evtx.record import RecordInfo
from hayabusa_py.rules.config import EventKeyAlias
from hayabusa_py.rules.yaml12 import YamlReal, as_i64


def _required_leaves(node: SelectionNode) -> set[LeafSelectionNode] | None:
    """Leaves that must match for ``node`` to match; ``None`` means 'unknown / no requirement'."""
    if isinstance(node, LeafSelectionNode):
        return {node}
    if isinstance(node, RefSelectionNode):
        return _required_leaves(node.selection_node)
    if isinstance(node, NotSelectionNode):
        return set()
    if isinstance(node, NarySelectionNode):
        if not node.child_nodes:
            return set()
        child_sets = [_required_leaves(child) or set() for child in node.child_nodes]
        if node.all_of:
            return set().union(*child_sets)
        common = set(child_sets[0])
        for child_set in child_sets[1:]:
            common = {leaf for leaf in common if any(_same_constraint(leaf, other) for other in child_set)}
        return common
    return set()


def _constraint(leaf: LeafSelectionNode) -> tuple[str, str] | None:
    """(field, exact value) for a plain ``Channel: x`` / ``EventID: n`` leaf, else None."""
    if len(leaf.key_list) != 1 or "|" in leaf.key_list[0]:
        return None
    key = leaf.key_list[0]
    value = leaf.select_value
    if key == "EventID":
        number = as_i64(value)
        if number is None:
            return None
        return ("EventID", str(number))
    if key == "Channel":
        if not isinstance(value, str) or isinstance(value, YamlReal):
            return None
        if any(ch in value for ch in "*?\\"):
            return None
        return ("Channel", value)
    return None


def _same_constraint(a: LeafSelectionNode, b: LeafSelectionNode) -> bool:
    if a is b:
        return True
    ca, cb = _constraint(a), _constraint(b)
    return ca is not None and ca == cb


class RuleIndex:
    """Rules bucketed by required (Channel, EventID); ``candidates`` returns rules to evaluate."""

    __slots__ = ("alias", "by_channel", "by_channel_eid", "by_eid", "unindexed")

    def __init__(self, alias: EventKeyAlias | None) -> None:
        self.alias = alias
        self.by_channel_eid: dict[tuple[str, str], list[RuleNode]] = defaultdict(list)
        self.by_channel: dict[str, list[RuleNode]] = defaultdict(list)
        self.by_eid: dict[str, list[RuleNode]] = defaultdict(list)
        self.unindexed: list[RuleNode] = []

    @classmethod
    def without_index(cls, rules: Iterable[RuleNode]) -> RuleIndex:
        index = cls(None)
        index.unindexed = list(rules)
        return index

    @classmethod
    def build(cls, rules: Iterable[RuleNode], alias: EventKeyAlias) -> RuleIndex:
        index = cls(alias)
        for rule in rules:
            condition = rule.detection.condition
            channel = eid = None
            if condition is not None:
                for leaf in _required_leaves(condition) or ():
                    constraint = _constraint(leaf)
                    if constraint is None:
                        continue
                    if constraint[0] == "Channel":
                        channel = constraint[1].lower()
                    else:
                        eid = constraint[1]
            if channel is not None and eid is not None:
                index.by_channel_eid[(channel, eid)].append(rule)
            elif channel is not None:
                index.by_channel[channel].append(rule)
            elif eid is not None:
                index.by_eid[eid].append(rule)
            else:
                index.unindexed.append(rule)
        return index

    def candidates(self, record: RecordInfo) -> list[RuleNode]:
        if self.alias is None:
            return self.unindexed
        channel = record.get_value("Channel")
        eid = record.get_value("EventID")
        result = list(self.unindexed)
        if channel is not None:
            channel_key = channel.lower()
            result.extend(self.by_channel.get(channel_key, ()))
            if eid is not None:
                result.extend(self.by_channel_eid.get((channel_key, eid), ()))
        if eid is not None:
            result.extend(self.by_eid.get(eid, ()))
        return result

    def describe(self) -> dict[str, int]:
        return {
            "channel+eid": sum(len(v) for v in self.by_channel_eid.values()),
            "channel": sum(len(v) for v in self.by_channel.values()),
            "eid": sum(len(v) for v in self.by_eid.values()),
            "unindexed": len(self.unindexed),
        }
