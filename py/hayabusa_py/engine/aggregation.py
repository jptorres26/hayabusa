"""Aggregation (``| count(...) by ... op N`` with ``timeframe``) — port of
``src/detections/rule/aggregation_parser.rs`` and ``src/detections/rule/count.rs``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from hayabusa_py.engine.timeutil import EPOCH_1977_NS, NANOS, get_event_time
from hayabusa_py.engine.values import MISSING, get_event_value, json_compact
from hayabusa_py.rules.config import EventKeyAlias

if TYPE_CHECKING:
    from hayabusa_py.engine.rule import RuleNode
    from hayabusa_py.evtx.record import RecordInfo

_TOKEN_PATTERNS = [
    re.compile(r"^count\( *\w* *\)"),
    re.compile(r"^ "),
    re.compile(r"^by"),
    re.compile(r"^=="),
    re.compile(r"^<="),
    re.compile(r"^>="),
    re.compile(r"^<"),
    re.compile(r"^>"),
    re.compile(r"^(\s*\w+\s*,)+\s*\w+|^\w+"),
]
_RE_PIPE = re.compile(r"\|.*")
_I64_RE = re.compile(r"^[-+]?[0-9]+$")


class AggregationParseError(ValueError):
    pass


class CmpOp(Enum):
    EQ = "=="
    LE = "<="
    LT = "<"
    GE = ">="
    GT = ">"


@dataclass(slots=True)
class AggregationParseInfo:
    """``count(field) by by_field op num``."""

    field_name: str | None
    by_field_name: str | None
    cmp_op: CmpOp
    cmp_num: int


_SPACE, _BY = " ", "by"


@dataclass(slots=True, frozen=True)
class _Count:
    field: str


@dataclass(slots=True, frozen=True)
class _Keyword:
    text: str


def _to_token(text: str) -> Any:
    if text.startswith("count("):
        return _Count(text.replace("count(", "", 1).replace(")", "", 1).replace(" ", ""))
    if text == " ":
        return _SPACE
    if text == "by":
        return _BY
    for op in CmpOp:
        if text == op.value:
            return op
    return _Keyword(text)


def tokenize(text: str) -> list[Any]:
    tokens: list[Any] = []
    rest = text
    while rest:
        for pattern in _TOKEN_PATTERNS:
            match = pattern.match(rest)
            if match:
                break
        else:
            raise AggregationParseError("An unusable character was found.")
        matched = match.group(0)
        rest = rest[len(matched) :]
        token = _to_token(matched)
        if token is _SPACE:
            continue
        tokens.append(token)
    return tokens


def _parse(tokens: list[Any]) -> AggregationParseInfo:
    if not tokens:
        raise AggregationParseError("There are no strings after the pipe(|).")
    iterator = iter(tokens)
    token = next(iterator)
    if not isinstance(token, _Count):
        raise AggregationParseError("The aggregation condition can only use count.")
    count_field = token.field or None
    token = next(iterator, None)
    if token is None:
        raise AggregationParseError("The count keyword needs a compare operator and number like '> 3'")
    by_field = None
    if token is _BY:
        after_by = next(iterator, None)
        if after_by is None or not isinstance(after_by, _Keyword):
            raise AggregationParseError("The by keyword needs a field name like 'by EventID'")
        by_field = after_by.text
        token = next(iterator, None)
    if token is None or not isinstance(token, CmpOp):
        raise AggregationParseError("The count keyword needs a compare operator and number like '> 3'")
    number_token = next(iterator, _SPACE)
    if not isinstance(number_token, _Keyword) or not _I64_RE.match(number_token.text):
        raise AggregationParseError("The compare operator needs a number like '> 3'.")
    if next(iterator, None) is not None:
        raise AggregationParseError("An unnecessary word was found.")
    return AggregationParseInfo(count_field, by_field, token, int(number_token.text))


def compile_aggregation(condition: str) -> AggregationParseInfo | None:
    """``AggregationConditionCompiler::compile``: None when the condition has no pipe."""
    match = _RE_PIPE.search(condition)
    if match is None:
        return None
    aggregation = match.group(0).replace("|", "", 1)
    try:
        return _parse(tokenize(aggregation))
    except AggregationParseError as error:
        raise AggregationParseError(f"An aggregation condition parse error has occurred. {error}") from None


# --------------------------------------------------------------------------------------------
# count.rs
# --------------------------------------------------------------------------------------------


@dataclass(slots=True)
class AggRecordTimeInfo:
    field_value: str
    time: int  # epoch nanoseconds
    event_id: str
    computer: str
    channel: str
    evtx_file_path: str


@dataclass(slots=True)
class AggResult:
    data: int
    key: str
    field_values: list[str]
    start_datetime: int  # epoch nanoseconds
    agg_record_time_info: list[AggRecordTimeInfo] = field(default_factory=list)


@dataclass(slots=True)
class TimeFrameInfo:
    """``timeframe: 15m`` -> unit ``m``, value 15. ``time_value`` is None when not an integer."""

    time_unit: str
    time_value: int | None
    error: str | None = None

    @classmethod
    def parse(cls, value: str) -> TimeFrameInfo:
        unit = ""
        target = value
        error = None
        for candidate in ("s", "m", "h", "d"):
            if value.endswith(candidate):
                unit = candidate
                break
        else:
            error = f"Timeframe is invalid. Input value:{value}"
        if unit:
            target = value[:-1]
        number = int(target) if _I64_RE.match(target) else None
        return cls(unit, number, error)

    def seconds(self) -> int | None:
        """``count::get_sec_timeframe``."""
        if self.time_value is None:
            return None
        if self.time_unit == "d":
            return self.time_value * 86400
        if self.time_unit == "h":
            return self.time_value * 3600
        if self.time_unit == "m":
            return self.time_value * 60
        return self.time_value


def _quoteless(value: Any) -> str:
    """``Value::to_string().replace('"', "")``."""
    return json_compact(value).replace('"', "")


def get_alias_value_in_record(alias: str, record: Any, eventkey_alias: EventKeyAlias, log: Callable[[str], None] | None = None, *, is_by_alias: bool = False, rule_file: str = "-") -> str | None:
    """``count::get_alias_value_in_record``: the value of ``alias`` with double quotes removed."""
    if not alias:
        return None
    value = get_event_value(alias, record, eventkey_alias)
    if value is MISSING:
        if log is not None:
            event_id = get_event_value("Event.System.EventID", record, eventkey_alias)
            event_id_text = "-" if event_id is MISSING else json_compact(event_id)
            clause = "count by clause" if is_by_alias else "count field clause"
            log(f"[ERROR] {clause} alias value not found in count process. rule file:{rule_file} EventID:{event_id_text}")
        return None
    return _quoteless(value)


def create_count_key(agg: AggregationParseInfo, record: Any, eventkey_alias: EventKeyAlias, log: Callable[[str], None] | None, rule_file: str) -> str:
    """``count::create_count_key``: the ``by`` grouping key, ``_`` when unavailable."""
    if agg.by_field_name is None:
        return "_"
    by_field = agg.by_field_name
    if "," in by_field:
        parts = []
        for key in by_field.split(","):
            value = get_alias_value_in_record(key.strip(), record, eventkey_alias, log, is_by_alias=True, rule_file=rule_file)
            parts.append("_" if value is None else value)
        return ",".join(parts)
    value = get_alias_value_in_record(by_field, record, eventkey_alias, log, is_by_alias=True, rule_file=rule_file)
    return "_" if value is None else value


def count(rule: RuleNode, record: RecordInfo, eventkey_alias: EventKeyAlias, log: Callable[[str], None] | None, json_input_flag: bool = False) -> None:
    """``count::count``: register a matching record under its grouping key."""
    agg = rule.detection.aggregation_condition
    assert agg is not None
    rule_file = rule.rule_file_name()
    key = create_count_key(agg, record.record, eventkey_alias, log, rule_file)
    field_value = get_alias_value_in_record(agg.field_name or "", record.record, eventkey_alias, log, rule_file=rule_file) or ""
    data = record.record
    time = get_event_time(data, json_input_flag)
    if time is None:
        time = EPOCH_1977_NS

    def system_text(key_name: str) -> str:
        value = get_event_value(key_name, data, eventkey_alias)
        if value is MISSING:
            return ""
        return json_compact(value).strip('"')

    rule.countdata.setdefault(key, []).append(
        AggRecordTimeInfo(
            field_value=field_value,
            time=time,
            event_id=system_text("Event.System.EventID"),
            computer=system_text("Event.System.Computer"),
            channel=system_text("Event.System.Channel"),
            evtx_file_path=record.evtx_filepath,
        )
    )


def select_aggcon(cnt: int, agg: AggregationParseInfo) -> bool:
    op = agg.cmp_op
    if op is CmpOp.EQ:
        return cnt == agg.cmp_num
    if op is CmpOp.GE:
        return cnt >= agg.cmp_num
    if op is CmpOp.GT:
        return cnt > agg.cmp_num
    if op is CmpOp.LE:
        return cnt <= agg.cmp_num
    if op is CmpOp.LT:
        return cnt < agg.cmp_num
    return False


class _FieldStrategy:
    """count(field): number of distinct field values in the window."""

    __slots__ = ("value_counts",)

    def __init__(self) -> None:
        self.value_counts: dict[str, int] = {}

    def add_data(self, idx: int, records: list[AggRecordTimeInfo]) -> None:
        if idx < 0 or idx >= len(records):
            return
        value = records[idx].field_value
        self.value_counts[value] = self.value_counts.get(value, 0) + 1

    def remove_data(self, idx: int, records: list[AggRecordTimeInfo]) -> None:
        if idx < 0 or idx >= len(records):
            return
        value = records[idx].field_value
        current = self.value_counts.get(value)
        if current is None:
            return
        if current <= 1:
            del self.value_counts[value]
        else:
            self.value_counts[value] = current - 1

    def count(self) -> int:
        return len(self.value_counts)

    def create_agg_result(self, records: list[AggRecordTimeInfo], cnt: int, key: str) -> AggResult:
        values = list(self.value_counts.keys())
        self.value_counts = {}
        return AggResult(len(values), key, values, records[0].time, list(records))


class _NoFieldStrategy:
    """count(): number of records in the window."""

    __slots__ = ("cnt",)

    def __init__(self) -> None:
        self.cnt = 0

    def add_data(self, idx: int, records: list[AggRecordTimeInfo]) -> None:
        if 0 <= idx < len(records):
            self.cnt += 1

    def remove_data(self, idx: int, records: list[AggRecordTimeInfo]) -> None:
        if 0 <= idx < len(records):
            self.cnt -= 1

    def count(self) -> int:
        return self.cnt

    def create_agg_result(self, records: list[AggRecordTimeInfo], cnt: int, key: str) -> AggResult:
        result = AggResult(cnt, key, [], records[0].time, list(records))
        self.cnt = 0
        return result


def _is_in_timeframe(left: int, right: int, frame: int, records: list[AggRecordTimeInfo]) -> bool:
    left_time, left_nano = divmod(records[left].time, NANOS)
    right_time, right_nano = divmod(records[right].time, NANOS)
    if right_nano > left_nano:
        right_time += 1
    return right_time - left_time <= frame


def judge_timeframe(agg: AggregationParseInfo, timeframe: TimeFrameInfo | None, time_records: list[AggRecordTimeInfo], key: str, log: Callable[[str], None] | None = None) -> list[AggResult]:
    """``count::judge_timeframe``: slide a window over the time-sorted records of one key."""
    results: list[AggResult] = []
    if not time_records:
        return results
    records = sorted(time_records, key=lambda info: info.time)
    def_frame = records[-1].time // NANOS - records[0].time // NANOS
    frame = def_frame
    if timeframe is not None:
        seconds = timeframe.seconds()
        if seconds is None:
            if log is not None:
                log("[ERROR] Timeframe number is invalid. timeframe. invalid digit found in string")
        else:
            frame = seconds
    counter: _FieldStrategy | _NoFieldStrategy = _FieldStrategy() if agg.field_name is not None else _NoFieldStrategy()
    left = 0
    right = 0
    data_len = len(records)
    while left < data_len and right < data_len + 1:
        while right < data_len and _is_in_timeframe(left, right, frame, records):
            counter.add_data(right, records)
            right += 1
        cnt = counter.count()
        if select_aggcon(cnt, agg):
            results.append(counter.create_agg_result(records[left:right], cnt, key))
            left = right
        else:
            counter.remove_data(left, records)
            left += 1
    return results


def aggregation_condition_select(rule: RuleNode, log: Callable[[str], None] | None = None) -> list[AggResult]:
    """``count::aggregation_condition_select``: evaluate every grouping key."""
    agg = rule.detection.aggregation_condition
    if agg is None:
        return []
    results: list[AggResult] = []
    for key, value in rule.countdata.items():
        results.extend(judge_timeframe(agg, rule.detection.timeframe, value, key, log))
    return results
