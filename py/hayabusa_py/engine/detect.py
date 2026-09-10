"""The scan: load rules, evaluate every record, collect detections (port of the parts of
``src/detections/detection.rs`` and ``src/main.rs`` that drive rule evaluation).

Records reach the engine as JSON objects in the evtx-crate layout (see
:mod:`hayabusa_py.engine.values`). Detections are returned as :class:`Detection` objects; the
output layer turns them into timeline rows.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hayabusa_py.engine.aggregation import AggResult
from hayabusa_py.engine.correlation import parse_correlation_rules
from hayabusa_py.engine.index import RuleIndex
from hayabusa_py.engine.matchers import MatcherContext
from hayabusa_py.engine.rule import CorrelationKind, RuleNode, create_rule, get_detection_keys
from hayabusa_py.engine.timeutil import NANOS, get_event_time
from hayabusa_py.evtx.record import RecordInfo, create_lazy_rec_info
from hayabusa_py.rules.config import RulesConfig
from hayabusa_py.rules.loader import LoadedRules, RuleFilterOptions, load_rules

Logger = Callable[[str], None] | None


@dataclass(slots=True)
class Detection:
    """One timeline row: a rule that matched a record, or an aggregation result."""

    rule: RuleNode
    record: RecordInfo | None = None
    agg_result: AggResult | None = None

    @property
    def is_aggregation(self) -> bool:
        return self.agg_result is not None

    def event_time(self, json_input_flag: bool = False) -> int:
        if self.agg_result is not None:
            return self.agg_result.start_datetime
        assert self.record is not None
        return get_event_time(self.record.record, json_input_flag) or 0


@dataclass(slots=True)
class RuleSet:
    """The compiled, filtered rules plus loading statistics."""

    rules: list[RuleNode]
    loaded: LoadedRules
    parse_errors: list[str] = field(default_factory=list)
    keys: list[str] = field(default_factory=list)

    @property
    def parse_error_count(self) -> int:
        return self.loaded.error_rule_count + len(self.parse_errors)


def load_rule_set(
    rules_path: str | Path,
    config: RulesConfig,
    options: RuleFilterOptions | None = None,
    log: Logger = None,
) -> RuleSet:
    """``Detection::parse_rule_files``: read, filter, compile and resolve correlation rules."""
    options = options or RuleFilterOptions()
    loaded = load_rules(rules_path, options, config.rule_exclude, config.expand_map, log)
    ctx = MatcherContext(windash_chars=config.windash_characters, base_dir=Path(rules_path).parent if Path(rules_path).is_dir() else None)
    parse_errors: list[str] = []
    rules: list[RuleNode] = []
    for path, doc in loaded.files:
        rule = create_rule(path, doc)
        errors = rule.init(ctx, log)
        if errors:
            parse_errors.append(f"Failed to parse rule file. (FilePath : {path})")
            parse_errors.extend(errors)
            if log is not None:
                log(f"[WARN] Failed to parse rule file. (FilePath : {path})")
                for error in errors:
                    log(f"[WARN] {error}")
            continue
        rules.append(rule)
    rules = parse_correlation_rules(rules, ctx, log, parse_errors)
    keys = sorted({key for rule in rules for key in get_detection_keys(rule)})
    return RuleSet(rules, loaded, parse_errors, keys)


@dataclass(slots=True)
class ScanStats:
    files: int = 0
    events: int = 0
    events_with_hits: int = 0
    detections: int = 0
    rules_evaluated: int = 0
    seconds: float = 0.0


class Detector:
    """Evaluates a :class:`RuleSet` against records and collects detections.

    Per-record rules are matched immediately; aggregation rules (``count()`` and correlation)
    accumulate in their ``countdata`` and are resolved by :meth:`finish`.
    """

    def __init__(self, rule_set: RuleSet, config: RulesConfig, *, use_index: bool = True, json_input_flag: bool = False, log: Logger = None) -> None:
        self.rule_set = rule_set
        self.config = config
        self.alias = config.eventkey_alias
        self.json_input_flag = json_input_flag
        self.log = log
        self.stats = ScanStats()
        self.index = RuleIndex.build(rule_set.rules, self.alias) if use_index else RuleIndex.without_index(rule_set.rules)
        self._agg_rules = [rule for rule in rule_set.rules if rule.has_agg_condition()]

    def scan_records(self, evtx_filepath: str, records: Iterable[Any], *, recovered: bool = False) -> Iterator[Detection]:
        """Evaluate every rule against every record of one file, yielding record detections."""
        alias = self.alias
        log = self.log
        json_input = self.json_input_flag
        stats = self.stats
        stats.files += 1
        started = time.perf_counter()
        for data in records:
            stats.events += 1
            info = create_lazy_rec_info(data, evtx_filepath, alias, recovered_record=recovered)
            hit = False
            candidates = self.index.candidates(info)
            stats.rules_evaluated += len(candidates)
            for rule in candidates:
                if not rule.select(info, alias, log, json_input):
                    continue
                hit = True
                if rule.has_agg_condition():
                    continue
                stats.detections += 1
                yield Detection(rule, info)
            if hit:
                stats.events_with_hits += 1
        stats.seconds += time.perf_counter() - started

    def finish(self) -> list[Detection]:
        """``Detection::add_aggcondition_msg``: resolve count() and correlation rules."""
        results: list[Detection] = []
        temporal_refs: dict[str, list[AggResult]] = defaultdict(list)
        for rule in self._agg_rules:
            for value in rule.judge_satisfy_aggcondition(self.log):
                output = True
                if rule.correlation_type.kind is CorrelationKind.TEMPORAL_REF:
                    temporal_refs[rule.correlation_type.ref_id].append(value)
                    output = rule.correlation_type.generate
                if output:
                    results.append(Detection(rule, None, value))
        for rule in self.rule_set.rules:
            kind = rule.correlation_type.kind
            if kind not in (CorrelationKind.TEMPORAL, CorrelationKind.TEMPORAL_ORDERED):
                continue
            ref_ids = rule.correlation_type.rules
            if not ref_ids or not all(ref_id in temporal_refs for ref_id in ref_ids):
                continue
            timeframe = rule.detection.timeframe
            seconds = timeframe.seconds() if timeframe is not None else None
            if seconds is None:
                continue
            data = {ref_id: temporal_refs[ref_id] for ref_id in ref_ids}
            for result in detect_within_timeframe(ref_ids, data, seconds * NANOS, kind is CorrelationKind.TEMPORAL_ORDERED):
                results.append(Detection(rule, None, result))
        self.stats.detections += len(results)
        return results


def detect_within_timeframe(ids: list[str], all_results: dict[str, list[AggResult]], timeframe_ns: int, temporal_ordered: bool) -> list[AggResult]:
    """``Detection::detect_within_timeframe``: base results of ``ids[0]`` for which every other
    referenced rule also produced a result (same group-by key) within the timeframe."""
    results: list[AggResult] = []
    if not ids:
        return results
    base_records = all_results.get(ids[0])
    if base_records is None:
        return results
    for base in base_records:
        found = False
        order_floor = base.start_datetime
        window_end = base.start_datetime + timeframe_ns
        for ref_id in ids[1:]:
            found = False
            targets = all_results.get(ref_id)
            if targets is None:
                break
            if temporal_ordered:
                candidates = [t.start_datetime for t in targets if t.key == base.key and order_floor <= t.start_datetime <= window_end]
                if candidates:
                    found = True
                    order_floor = min(candidates)
            else:
                found = any(
                    t.key == base.key and base.start_datetime - timeframe_ns <= t.start_datetime <= base.start_datetime + timeframe_ns
                    for t in targets
                )
            if not found:
                break
        if found:
            results.append(base)
    return results
