"""Sigma v2 correlation rules (port of ``src/detections/rule/correlation_parser.rs``).

``event_count``/``value_count`` rules are merged with the rules they reference into one rule
whose condition is an OR over the referenced conditions plus a ``count()`` aggregation.
``temporal``/``temporal_ordered`` rules get, per referenced rule, a ``TemporalRef`` copy that
aggregates ``count() >= 1`` per group-by/timespan; the temporal rule itself is evaluated at the
end from those results (see :func:`hayabusa_py.engine.detect.detect_within_timeframe`).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from hayabusa_py.engine.aggregation import AggregationParseInfo, CmpOp, TimeFrameInfo
from hayabusa_py.engine.matchers import MatcherContext
from hayabusa_py.engine.rule import CorrelationKind, CorrelationType, DetectionNode, RuleNode
from hayabusa_py.engine.selection import NarySelectionNode, SelectionNode
from hayabusa_py.rules.yaml12 import as_i64, as_str

Logger = Callable[[str], None] | None

_CMP = {"eq": CmpOp.EQ, "lte": CmpOp.LE, "gte": CmpOp.GE, "lt": CmpOp.LT, "gt": CmpOp.GT}


class CorrelationError(ValueError):
    pass


def is_referenced_rule(rule: RuleNode, id_or_title: str) -> bool:
    yaml = rule.yaml
    return any(as_str(yaml.get(key)) == id_or_title for key in ("id", "title", "name"))


def parse_condition(correlation: Any) -> tuple[CmpOp, int, str | None]:
    """``correlation.condition`` -> (operator, threshold, value_count field)."""
    if not isinstance(correlation, dict):
        raise CorrelationError("Failed to parse condition")
    condition = correlation.get("condition")
    if not isinstance(condition, dict):
        raise CorrelationError("Failed to parse condition")
    field = None
    if as_str(correlation.get("type")) == "value_count":
        for key, value in condition.items():
            if key == "field":
                field = as_str(value)
    for key, value in condition.items():
        if key in _CMP:
            number = as_i64(value)
            if number is None:
                raise CorrelationError("Failed to convert condition value to i64")
            return _CMP[key], number, field
    raise CorrelationError("Failed to match any condition")


def get_related_rules_id(yaml: Any) -> list[str]:
    correlation = yaml.get("correlation")
    if not isinstance(correlation, dict):
        raise CorrelationError("Failed to get 'correlation'")
    if "rules" not in correlation:
        raise CorrelationError("Failed to get 'rules'")
    rules = correlation["rules"]
    if not isinstance(rules, list):
        raise CorrelationError("Failed to convert 'rules' to Vec")
    out = []
    for rule in rules:
        text = as_str(rule)
        if text is None:
            raise CorrelationError("Failed to convert rule to string")
        out.append(text)
    return out


def get_group_by(yaml: Any) -> str | None:
    correlation = yaml.get("correlation")
    if not isinstance(correlation, dict):
        raise CorrelationError("Failed to get 'correlation'")
    if "group-by" not in correlation:
        return None
    group_by = correlation["group-by"]
    parts = [as_str(item) for item in group_by] if isinstance(group_by, list) else []
    return ",".join(part for part in parts if part is not None)


def parse_tframe(value: str) -> TimeFrameInfo:
    info = TimeFrameInfo.parse(value)
    if info.error:
        raise CorrelationError("Invalid time frame")
    return info


def _create_related_rule_nodes(referenced: list[str], other_rules: list[RuleNode], ctx: MatcherContext) -> tuple[list[RuleNode], dict[str, SelectionNode]]:
    related: list[RuleNode] = []
    name_to_selection: dict[str, SelectionNode] = {}
    for ref in referenced:
        found = False
        for other in other_rules:
            if is_referenced_rule(other, ref):
                found = True
                node = RuleNode(other.rule_path, other.yaml)
                node.init(ctx)
                name_to_selection.update(node.detection.name_to_selection)
                related.append(node)
        if not found:
            raise CorrelationError(f"The referenced rule was not found: {ref}")
    return related, name_to_selection


def _create_detection(rule: RuleNode, related: list[RuleNode], name_to_selection: dict[str, SelectionNode]) -> DetectionNode:
    cmp_op, number, field = parse_condition(rule.yaml.get("correlation"))
    group_by = get_group_by(rule.yaml)
    timespan = as_str(rule.yaml["correlation"].get("timespan"))
    if timespan is None:
        raise CorrelationError("Failed to get 'timespan'")
    time_frame = parse_tframe(timespan)
    or_node = NarySelectionNode.or_()
    for node in related:
        if node.detection.condition is not None:
            or_node.child_nodes.append(node.detection.condition)
    detection = DetectionNode()
    detection.name_to_selection = name_to_selection
    detection.condition = or_node
    detection.aggregation_condition = AggregationParseInfo(field, group_by, cmp_op, number)
    detection.timeframe = time_frame
    return detection


def _merge_referenced_rule(rule: RuleNode, other_rules: list[RuleNode], ctx: MatcherContext, log: Logger, errors: list[str]) -> RuleNode:
    def fail(reason: str) -> RuleNode:
        message = f"Failed to parse rule. (FilePath : {rule.rule_path}) {reason}"
        errors.append(message)
        if log is not None:
            log(f"[WARN] {message}")
        return rule

    correlation = rule.yaml.get("correlation") or {}
    rule_type = as_str(correlation.get("type"))
    if rule_type not in ("event_count", "value_count", "temporal", "temporal_ordered"):
        return fail("The type of correlation rule only supports event_count/value_count/temporal/temporal_ordered.")
    try:
        referenced = get_related_rules_id(rule.yaml)
    except CorrelationError:
        return fail("Referenced rule not found.")
    if not referenced:
        return fail("Referenced rule not found.")
    if as_str(correlation.get("timespan")) is None:
        return fail("key timespan not found.")
    if not isinstance(correlation.get("group-by"), list):
        return fail("key group-by  not found.")
    if rule_type in ("temporal", "temporal_ordered"):
        return rule
    try:
        related, name_to_selection = _create_related_rule_nodes(referenced, other_rules, ctx)
    except CorrelationError as error:
        return fail(str(error))
    if correlation.get("generate") is not True:
        other_rules[:] = [other for other in other_rules if not any(as_str(other.yaml.get(key)) in referenced for key in ("id", "title", "name"))]
    try:
        detection = _create_detection(rule, related, name_to_selection)
    except CorrelationError as error:
        return fail(str(error))
    merged_yaml = dict(rule.yaml)
    merged_yaml["detection"] = [node.yaml for node in related]
    return RuleNode(rule.rule_path, merged_yaml, detection)


def _parse_temporal_rules(temporal_rules: list[RuleNode], other_rules: list[RuleNode], ctx: MatcherContext) -> list[RuleNode]:
    parsed: list[RuleNode] = []
    ref_rules: list[RuleNode] = []
    delete_ids: set[str] = set()
    for temporal in temporal_rules:
        correlation = temporal.yaml.get("correlation") or {}
        ref_ids_yaml = correlation.get("rules")
        if not isinstance(ref_ids_yaml, list):
            continue
        generate = correlation.get("generate") is True
        timespan = as_str(correlation.get("timespan"))
        if timespan is None:
            continue
        group_by = get_group_by(temporal.yaml)
        time_frame = parse_tframe(timespan)
        new_ref_ids: list[str] = []
        for ref in ref_ids_yaml:
            ref_id = as_str(ref) or ""
            for other in other_rules:
                if not is_referenced_rule(other, ref_id):
                    continue
                if other.correlation_type.kind is not CorrelationKind.NONE:
                    other.correlation_type = CorrelationType(CorrelationKind.TEMPORAL_REF, [], generate, ref_id)
                    new_ref_ids.append(ref_id)
                    continue
                new_id = str(uuid.uuid4())
                new_yaml = dict(other.yaml)
                new_yaml["id"] = new_id
                node = RuleNode(other.rule_path, new_yaml)
                node.init(ctx)
                node.correlation_type = CorrelationType(CorrelationKind.TEMPORAL_REF, [], generate, new_id)
                detection = DetectionNode()
                detection.name_to_selection = node.detection.name_to_selection
                detection.condition = node.detection.condition
                detection.timeframe = time_frame
                detection.aggregation_condition = AggregationParseInfo(None, group_by, CmpOp.GE, 1)
                node.detection = detection
                ref_rules.append(node)
                new_ref_ids.append(new_id)
                if not generate:
                    delete_ids.add(ref_id)
        new_yaml = dict(temporal.yaml)
        new_yaml["correlation"] = dict(correlation, rules=new_ref_ids)
        node = RuleNode(temporal.rule_path, new_yaml)
        node.detection.aggregation_condition = AggregationParseInfo(None, group_by, CmpOp.GE, 1)
        node.detection.timeframe = time_frame
        parsed.append(node)
    other_rules[:] = [
        rule for rule in other_rules if not any((as_str(rule.yaml.get(key)) or "") in delete_ids for key in ("id", "title", "name"))
    ]
    other_rules.extend(ref_rules)
    return parsed


def parse_correlation_rules(rules: list[RuleNode], ctx: MatcherContext, log: Logger = None, errors: list[str] | None = None) -> list[RuleNode]:
    """``correlation_parser::parse_correlation_rules``: rewrite the rule set so correlation rules
    become directly evaluable RuleNodes. ``errors`` collects parse failures (also counted by the
    caller as rule parse errors)."""
    errors = errors if errors is not None else []
    correlation_rules = [rule for rule in rules if "correlation" in rule.yaml]
    not_correlation = [rule for rule in rules if "correlation" not in rule.yaml]
    temporal = [rule for rule in correlation_rules if as_str((rule.yaml.get("correlation") or {}).get("type")) in ("temporal", "temporal_ordered")]
    not_temporal = [rule for rule in correlation_rules if rule not in temporal]
    parsed = [_merge_referenced_rule(rule, not_correlation, ctx, log, errors) for rule in not_temporal]
    parsed.extend(not_correlation)
    parsed.extend(_parse_temporal_rules(temporal, parsed, ctx))
    return parsed
