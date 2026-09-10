"""Rule and detection nodes (port of ``src/detections/rule/rulenode.rs``)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePath
from typing import Any

from hayabusa_py.engine.aggregation import (
    AggregationParseError,
    AggregationParseInfo,
    AggResult,
    TimeFrameInfo,
    aggregation_condition_select,
    compile_aggregation,
    count,
)
from hayabusa_py.engine.condition import ConditionParseError, compile_condition
from hayabusa_py.engine.matchers import MatcherContext
from hayabusa_py.engine.selection import (
    LeafSelectionNode,
    SelectionNode,
    parse_selection_recursively,
)
from hayabusa_py.evtx.record import RecordInfo
from hayabusa_py.rules.config import EventKeyAlias
from hayabusa_py.rules.yaml12 import as_str

Logger = Callable[[str], None] | None


class CorrelationKind(Enum):
    NONE = "none"
    EVENT_COUNT = "event_count"
    VALUE_COUNT = "value_count"
    TEMPORAL = "temporal"
    TEMPORAL_ORDERED = "temporal_ordered"
    TEMPORAL_REF = "temporal_ref"


@dataclass(slots=True)
class CorrelationType:
    """``rulenode::CorrelationType``."""

    kind: CorrelationKind = CorrelationKind.NONE
    rules: list[str] = field(default_factory=list)  # referenced rule ids/titles for temporal*
    generate: bool = False  # TemporalRef: output the referenced rule's own matches too
    ref_id: str = ""  # TemporalRef: the correlation rule this rule feeds

    @classmethod
    def from_yaml(cls, yaml: Any) -> CorrelationType:
        correlation = yaml.get("correlation") if isinstance(yaml, dict) else None
        if not isinstance(correlation, dict):
            return cls()
        kind = as_str(correlation.get("type"))
        if kind is None:
            return cls()
        if kind == "event_count":
            return cls(CorrelationKind.EVENT_COUNT)
        if kind == "value_count":
            return cls(CorrelationKind.VALUE_COUNT)
        if kind in ("temporal", "temporal_ordered"):
            rules = [str(rule) for rule in (correlation.get("rules") or [])]
            return cls(CorrelationKind.TEMPORAL if kind == "temporal" else CorrelationKind.TEMPORAL_ORDERED, rules)
        return cls()


class DetectionNode:
    """``rulenode::DetectionNode``: the compiled ``detection`` section of a rule."""

    __slots__ = ("aggregation_condition", "condition", "name_to_selection", "timeframe")

    def __init__(self) -> None:
        self.name_to_selection: dict[str, SelectionNode] = {}
        self.condition: SelectionNode | None = None
        self.aggregation_condition: AggregationParseInfo | None = None
        self.timeframe: TimeFrameInfo | None = None

    def init(self, detection_yaml: Any, ctx: MatcherContext, log: Logger = None) -> list[str]:
        errors = self._parse_name_to_selection(detection_yaml, ctx)
        if errors:
            return errors
        timeframe = as_str(detection_yaml.get("timeframe"))
        if timeframe is not None:
            self.timeframe = TimeFrameInfo.parse(timeframe)
            if self.timeframe.error and log is not None:
                log(f"[ERROR] {self.timeframe.error}")
        condition = as_str(detection_yaml.get("condition"))
        if condition is None:
            if len(self.name_to_selection) >= 2:
                return ["There is no condition node under detection."]
            condition = next(iter(self.name_to_selection))
        errors = []
        try:
            self.condition = compile_condition(condition, self.name_to_selection)
        except ConditionParseError as error:
            errors.append(str(error))
        try:
            self.aggregation_condition = compile_aggregation(condition)
        except AggregationParseError as error:
            errors.append(str(error))
        return errors

    def select(self, record: RecordInfo, alias: EventKeyAlias) -> bool:
        if self.condition is None:
            return False
        return self.condition.select(record, alias)

    def _parse_name_to_selection(self, detection_yaml: Any, ctx: MatcherContext) -> list[str]:
        if not isinstance(detection_yaml, dict):
            return ["Detection node was not found."]
        errors: list[str] = []
        for key, value in detection_yaml.items():
            name = key if isinstance(key, str) else ""
            if not name or name in ("condition", "timeframe"):
                continue
            node = parse_selection_recursively([], value)
            init_errors = node.init(ctx)
            if init_errors:
                errors.extend(init_errors)
            else:
                self.name_to_selection[name] = node
        if errors:
            return errors
        if not self.name_to_selection:
            return ["There is no selection node under detection."]
        return []


class RuleNode:
    """``rulenode::RuleNode``: one loaded rule file."""

    __slots__ = ("correlation_type", "countdata", "detection", "rule_path", "yaml")

    def __init__(self, rule_path: str, yaml: Any, detection: DetectionNode | None = None) -> None:
        self.rule_path = rule_path
        self.yaml = yaml if isinstance(yaml, dict) else {}
        self.detection = detection if detection is not None else DetectionNode()
        self.countdata: dict[str, list[Any]] = {}
        self.correlation_type = CorrelationType.from_yaml(self.yaml)

    # -- convenience accessors ---------------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        return self.yaml.get(key, default)

    def get_str(self, key: str, default: str = "-") -> str:
        value = as_str(self.yaml.get(key))
        return default if value is None else value

    @property
    def rule_id(self) -> str:
        return self.get_str("id")

    @property
    def title(self) -> str:
        return self.get_str("title")

    @property
    def level(self) -> str:
        return self.get_str("level")

    def rule_file_name(self) -> str:
        return PurePath(self.rule_path).name or "-"

    # -- lifecycle ---------------------------------------------------------------------------
    def init(self, ctx: MatcherContext, log: Logger = None) -> list[str]:
        """Compile the detection section. Correlation rules are assembled later by the
        correlation parser, so they have nothing to initialize here."""
        if "correlation" in self.yaml:
            return []
        return self.detection.init(self.yaml.get("detection"), ctx, log)

    def select(self, record: RecordInfo, alias: EventKeyAlias, log: Logger = None, json_input_flag: bool = False) -> bool:
        result = self.detection.select(record, alias)
        if result and self.has_agg_condition():
            count(self, record, alias, log, json_input_flag)
        return result

    def has_agg_condition(self) -> bool:
        return self.detection.aggregation_condition is not None

    def judge_satisfy_aggcondition(self, log: Logger = None) -> list[AggResult]:
        if not self.has_agg_condition():
            return []
        return aggregation_condition_select(self, log)

    def check_exist_countdata(self) -> bool:
        return bool(self.countdata)

    def get_agg_condition(self) -> AggregationParseInfo | None:
        return self.detection.aggregation_condition


def create_rule(rule_path: str, yaml: Any) -> RuleNode:
    return RuleNode(rule_path, yaml)


def get_detection_keys(rule: RuleNode) -> list[str]:
    """``rulenode::get_detection_keys``: every field key referenced by the rule's leaves."""
    keys: list[str] = []
    for selection in rule.detection.name_to_selection.values():
        for node in selection.get_descendants():
            if isinstance(node, LeafSelectionNode):
                keys.extend(key for key in node.get_keys() if key)
    return keys
