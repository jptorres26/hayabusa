"""Turn detections into output rows (port of ``Detection::create_log_record`` /
``create_agg_log_record`` in ``src/detections/detection.rs``, ``message::create_message`` /
``parse_message`` in ``src/detections/message.rs``, ``utils::create_recordinfos`` and
``src/level.rs``)."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any

from hayabusa_py.engine.aggregation import AggRecordTimeInfo, AggResult
from hayabusa_py.engine.detect import Detection
from hayabusa_py.engine.rule import RuleNode
from hayabusa_py.engine.timeutil import EPOCH_1970_NS, format_time, get_event_time
from hayabusa_py.engine.values import serde_number_to_string, value_to_string, walk_path
from hayabusa_py.output.config import GEOIP_KINDS, OutputConfig, ProfileColumn, convert_field_data
from hayabusa_py.rules.config import EventKeyAlias
from hayabusa_py.rules.loader import level_index
from hayabusa_py.rules.yaml12 import as_str

SEP = " ¦ "
ALIAS_RE = re.compile(r"%[a-zA-Z0-9-_\[\]]+%")
SUFFIX_RE = re.compile(r"\[([0-9]+)\]")

LEVEL_FULL = {0: "undefined", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "emergency"}
LEVEL_ABBREV = {0: "undef", 1: "info", 2: "low", 3: "med", 4: "high", 5: "crit", 6: "emer"}


def level_convert(level: int, computer: str, critical_systems: set[str]) -> int:
    """``LEVEL::convert``: bump the level by one for events from a critical system."""
    if not critical_systems:
        return level
    for name in computer.split(SEP):
        if name in critical_systems:
            if level == 0 or level == 1:
                return level
            return min(level + 1, 6)
    return level


def is_control(ch: str) -> bool:
    return unicodedata.category(ch) == "Cc"


def remove_sp_char(text: str) -> str:
    """``utils::remove_sp_char``: collapse runs of spaces, drop control characters except
    ``\\n``/``\\r``/``\\t``, trim spaces."""
    out: list[str] = []
    prev = "a"
    for ch in text:
        drop = (prev == " " and ch == " ") or (is_control(ch) and ch not in "\n\r\t")
        if not drop:
            prev = ch
            out.append(ch)
    return "".join(out).strip(" ")


def make_ascii_titlecase(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    first = stripped[0]
    if not first.isascii():
        return text
    return first.upper() + stripped[1:]


def collapse_whitespace(text: str) -> str:
    """Rust ``split_ascii_whitespace().join(" ")``."""
    return " ".join(text.split())


@dataclass(slots=True)
class DetectInfo:
    """``message::DetectInfo``: one rendered detection."""

    detected_time: int
    rule_path: str
    ruleid: str
    ruletitle: str
    ruleauthor: str
    level: int
    computername: str
    rec_id: str
    eventid: str
    detail: str
    output_fields: list[tuple[str, str, str]]  # (column, kind, value)
    agg_result: AggResult | None = None
    details_convert_map: dict[str, list[str]] = field(default_factory=dict)


# --------------------------------------------------------------------------------------------
# AllFieldInfo (utils::create_recordinfos)
# --------------------------------------------------------------------------------------------


def _clean_value(text: str) -> str:
    out = []
    for ch in text:
        if (is_control(ch) or ch in " \t\n\r\x0c") and ch not in "\r\n\t":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _collect_recordinfo(keys: list[str], parent_key: str, arr_index: int, org: Any, cur: Any, output: set[tuple[str, str]], config: OutputConfig, map_key: tuple[str, str]) -> None:
    if isinstance(cur, list):
        for index, sub in enumerate(cur):
            _collect_recordinfo(keys, parent_key, index, org, sub, output, config, map_key)
        return
    if isinstance(cur, dict):
        if parent_key:
            keys.append(parent_key)
        for key, value in cur.items():
            if key == "xmlns":
                continue
            if key == "System" and (keys[0] if keys else "") == "Event":
                continue
            _collect_recordinfo(keys, key, -1, org, value, output, config, map_key)
        if parent_key:
            keys.pop()
        return
    if cur is None:
        return
    text = value_to_string(cur)
    if text is None:
        return
    text = _clean_value(text)
    if arr_index >= 0:
        field_name = f"{parent_key}[{arr_index + 1}]"
        converted = convert_field_data(config.field_data_map, map_key, field_name.lower(), text, org)
        if converted is not None:
            text = converted
        output.add((field_name, text))
    else:
        output.add((parent_key, text))


def create_recordinfos(record: Any, map_key: tuple[str, str], config: OutputConfig) -> list[str]:
    """``utils::create_recordinfos``: sorted ``key: value`` lines for every leaf field."""
    output: set[tuple[str, str]] = set()
    _collect_recordinfo([], "", -1, record, record, output, config, map_key)
    lines = []
    for key, value in sorted(output):
        converted = convert_field_data(config.field_data_map, map_key, key.lower(), value, record)
        lines.append(f"{key}: {remove_sp_char(converted if converted is not None else value)}")
    return lines


# --------------------------------------------------------------------------------------------
# parse_message / create_message
# --------------------------------------------------------------------------------------------


def parse_message(record: Any, output: str, alias: EventKeyAlias, json_timeline: bool, map_key: tuple[str, str], config: OutputConfig) -> tuple[str, list[str]]:
    """``message::parse_message``."""
    return_message = output
    hash_map: list[tuple[str, list[str]]] = []
    details_key = output.split(SEP)
    for match in ALIAS_RE.finditer(output):
        full_target = match.group(0)
        target = full_target[1:-1]
        event_key_path = alias.get(target)
        if event_key_path is None:
            event_key_path = f"Event.EventData.{target}"
        current, field_name = walk_path(record, event_key_path)
        suffix_match = SUFFIX_RE.search(target)
        suffix = -1
        if suffix_match:
            try:
                suffix = int(suffix_match.group(1))
            except ValueError:
                suffix = -1
        if suffix >= 1:
            data = current.get("Data") if isinstance(current, dict) else None
            base = data if data is not None else current
            element = None
            if isinstance(base, list) and suffix - 1 < len(base):
                element = base[suffix - 1]
            current = element if element is not None else current
            field_name = target
        value = serde_number_to_string(current)
        if value is not None:
            if config.field_data_map is None or not field_name:
                field_data = value
            else:
                converted = convert_field_data(config.field_data_map, map_key, field_name.lower(), value, record)
                field_data = converted if converted is not None else value
            if json_timeline:
                hash_map.append((full_target, [field_data]))
            else:
                hash_map.append((full_target, [collapse_whitespace(field_data)]))
        else:
            hash_map.append((full_target, ["n/a"]))
    details_key_and_value: list[str] = []
    for placeholder, values in hash_map:
        if not json_timeline:
            return_message = return_message.replace(placeholder, values[0])
        for contents in details_key:
            if placeholder in contents:
                key = contents.split(": ", 1)[0] if ": " in contents else ""
                details_key_and_value.append(f"{key}: {values[0]}")
                break
    if not hash_map:
        for contents in details_key:
            if ": " in contents:
                key, val = contents.split(": ", 1)
            else:
                key, val = "", ""
            details_key_and_value.append(f"{key}: {val}")
    return return_message, details_key_and_value


def create_message(record: Any, output: str, info: DetectInfo, converter: dict[str, tuple[str, str]], is_agg: bool, json_timeline: bool, alias: EventKeyAlias, map_key: tuple[str, str], config: OutputConfig) -> DetectInfo:
    """``message::create_message``: fill every profile column of ``info.output_fields``."""
    details_map: dict[str, list[str]] = {}
    special_char_removed: list[str] = []
    if not is_agg:
        parsed_detail, details_in_record = parse_message(record, output, alias, json_timeline, map_key, config)
        special_char_removed = [remove_sp_char(detail) for detail in details_in_record]
        if json_timeline:
            details_map["#Details"] = list(special_char_removed)
        parsed_detail = remove_sp_char(parsed_detail)
        info.detail = parsed_detail if parsed_detail else "-"
    elif output != "-":
        details_map["#Details"] = [output]
    elif info.detail != "-":
        details_map["#Details"] = [info.detail]
    else:
        details_map["#Details"] = ["-"]

    replaced: list[tuple[str, str, str]] = []
    exist_all_field_info = False
    for column, kind, value in info.output_fields:
        if kind == "Details":
            if not info.detail:
                replaced.append((column, kind, value))
            else:
                replaced.append((column, kind, info.detail))
                info.detail = ""
        elif kind == "AllFieldInfo":
            exist_all_field_info = True
            if is_agg:
                replaced.append((column, kind, info.detail))
                if json_timeline:
                    details_map["#AllFieldInfo"] = [info.detail]
            else:
                all_field_infos = details_map.get("#AllFieldInfo")
                if all_field_infos is None:
                    all_field_infos = create_recordinfos(record, map_key, config)
                if json_timeline:
                    details_map["#AllFieldInfo"] = all_field_infos
                    replaced.append((column, kind, ""))
                    continue
                replaced.append((column, kind, SEP.join(all_field_infos) if all_field_infos else "-"))
        elif kind == "Literal":
            replaced.append((column, kind, value))
        elif kind == "ExtraFieldInfo":
            if is_agg:
                if json_timeline:
                    details_map["#ExtraFieldInfo"] = ["-"]
                replaced.append((column, kind, "-"))
                continue
            details_splits = set()
            for detail in special_char_removed:
                detail_value = detail.split(": ", 1)[1] if ": " in detail else ""
                details_splits.add(detail_value[:-1] if detail_value.endswith(",") else detail_value)
            all_field_infos = details_map.get("#AllFieldInfo")
            if all_field_infos is None:
                all_field_infos = create_recordinfos(record, map_key, config)
                details_map["#AllFieldInfo"] = list(all_field_infos)
            extra = sorted(
                line for line in all_field_infos if (line.split(": ", 1)[1] if ": " in line else "") not in details_splits
            )
            if json_timeline:
                details_map["#ExtraFieldInfo"] = extra
                replaced.append((column, kind, "-"))
            elif not extra:
                replaced.append((column, kind, "-"))
            else:
                replaced.append((column, kind, SEP.join(extra)))
        elif kind in GEOIP_KINDS:
            converted = converter.get(column)
            replaced.append((column, kind, converted[1] if converted else value))
        else:
            converted = converter.get(column)
            if converted is not None:
                parsed, _ = parse_message(record, converted[1], alias, json_timeline, map_key, config)
                replaced.append((column, kind, parsed))
    if not exist_all_field_info:
        details_map.pop("#AllFieldInfo", None)
    info.output_fields = replaced
    info.details_convert_map = details_map
    return info


# --------------------------------------------------------------------------------------------
# create_log_record / create_agg_log_record
# --------------------------------------------------------------------------------------------


def _system_text(record: Any, *path: str) -> str:
    current = record
    for segment in path:
        if isinstance(current, dict):
            current = current.get(segment)
        else:
            current = None
            break
    return serde_number_to_string(current) or ""


def get_tag_info(rule: RuleNode, config: OutputConfig) -> list[str]:
    tags = rule.yaml.get("tags")
    if not isinstance(tags, list):
        return []
    out = []
    for tag in tags:
        text = as_str(tag) or ""
        out.append(config.tags_config.get(text, text))
    return out


def _tag_columns(tag_info: list[str], config: OutputConfig) -> tuple[str, str, str]:
    values = set(config.tags_config.values())
    tactics = [tag.split(",")[0] for tag in tag_info if tag in values]
    techniques = [make_ascii_titlecase(tag.replace("attack.", "")) for tag in tag_info if tag not in values and tag.startswith(("attack.t", "attack.g", "attack.s"))]
    others = [tag for tag in tag_info if not (tag in values or tag.startswith(("attack.t", "attack.g", "attack.s")))]
    return SEP.join(tactics), SEP.join(techniques), SEP.join(others)


def _channel_display(channel: str, config: OutputConfig) -> str:
    abbreviated = config.channel_abbr.get(channel.lower(), channel)
    return config.generic_abbr.replace_all(abbreviated)


def _level_text(level: int, config: OutputConfig) -> str:
    text = LEVEL_FULL[level] if config.disable_abbreviation else LEVEL_ABBREV[level]
    return text.strip() if config.output_to_file else text


def _rule_meta(rule: RuleNode, column: ProfileColumn, converter: dict[str, tuple[str, str]]) -> None:
    kind = column.kind
    if kind == "RuleTitle":
        converter[column.name] = (kind, as_str(rule.yaml.get("title")) or "")
    elif kind == "RuleFile":
        converter[column.name] = (kind, PurePath(rule.rule_path).name)
    elif kind == "RuleAuthor":
        converter[column.name] = (kind, as_str(rule.yaml.get("author")) or "-")
    elif kind == "RuleCreationDate":
        converter[column.name] = (kind, as_str(rule.yaml.get("date")) or "-")
    elif kind == "RuleModifiedDate":
        converter[column.name] = (kind, as_str(rule.yaml.get("modified")) or "")
    elif kind == "Status":
        converter[column.name] = (kind, as_str(rule.yaml.get("status")) or "-")
    elif kind == "RuleID":
        converter[column.name] = (kind, as_str(rule.yaml.get("id")) or "-")


def create_log_record(detection: Detection, config: OutputConfig, alias: EventKeyAlias) -> DetectInfo:
    """``Detection::create_log_record``."""
    rule = detection.rule
    info = detection.record
    assert info is not None
    record = info.record
    tag_info = get_tag_info(rule, config)
    rec_id = _system_text(record, "Event", "System", "EventRecordID") if config.include_record_id else ""
    channel = _system_text(record, "Event", "System", "Channel")
    provider = _system_text(record, "Event", "System", "Provider_attributes", "Name").replace("'", "")
    eid = _system_text(record, "Event", "System", "EventID")
    recovered = "Y" if info.recovered_record else ""
    time = get_event_time(record, config.json_input)
    if time is None:
        time = EPOCH_1970_NS
    level = level_index(as_str(rule.yaml.get("level")) or "-")
    computer_name = ""
    try:
        computer_raw = record["Event"]["System"]["Computer"]
    except (KeyError, TypeError):
        computer_raw = None
    if isinstance(computer_raw, str):
        computer_name = computer_raw.replace('"', "")
    tactics, techniques, others = _tag_columns(tag_info, config)
    converter: dict[str, tuple[str, str]] = {}
    for column in config.profiles:
        kind = column.kind
        if kind == "Timestamp":
            converter[column.name] = (kind, format_time(time, False, config.time_format))
        elif kind == "Computer":
            converter[column.name] = (kind, computer_name)
        elif kind == "Channel":
            converter[column.name] = (kind, _channel_display(channel, config))
        elif kind == "Level":
            level = level_convert(level, computer_name, config.critical_systems)
            converter[column.name] = (kind, _level_text(level, config))
        elif kind == "EventID":
            converter[column.name] = (kind, eid)
        elif kind == "RecordID":
            converter[column.name] = (kind, rec_id)
        elif kind == "EvtxFile":
            converter[column.name] = (kind, info.evtx_filepath)
        elif kind == "MitreTactics":
            converter[column.name] = (kind, tactics)
        elif kind == "MitreTags":
            converter[column.name] = (kind, techniques)
        elif kind == "OtherTags":
            converter[column.name] = (kind, others)
        elif kind == "Provider":
            provider_value = _system_text(record, "Event", "System", "Provider_attributes", "Name")
            if provider_value == "":
                try:
                    raw = record["Event"]["System"]["Provider_attributes"]["Name"]
                except (KeyError, TypeError):
                    raw = None
                provider_value = "null" if raw is None else str(raw)
            provider_value = provider_value.replace('"', "")
            converter[column.name] = (kind, config.generic_abbr.replace_all(config.provider_abbr.get(provider_value, provider_value)))
        elif kind == "RecoveredRecord":
            converter["RecoveredRecord"] = (kind, recovered)
        elif kind == "RenderedMessage":
            try:
                message = record["Event"]["RenderingInfo"]["Message"]
            except (KeyError, TypeError):
                message = None
            if isinstance(message, str):
                converted = "\\r\\n".join(part.strip() for part in message.replace("\t", "\\t").split("\r\n"))
            else:
                converted = "n/a"
            converter[column.name] = (kind, converted)
        elif kind in GEOIP_KINDS:
            prefix = kind[:3]
            for suffix in ("ASN", "Country", "City"):
                converter.setdefault(prefix + suffix, (prefix + suffix, ""))
        else:
            _rule_meta(rule, column, converter)
    map_key = (channel.lower(), eid) if config.field_data_map is not None else ("", "")
    details = as_str(rule.yaml.get("details"))
    if details is None:
        details = config.default_details.get(f"{provider}_{eid}")
        if details is None:
            details = SEP.join(create_recordinfos(record, map_key, config))
    detect_info = DetectInfo(
        detected_time=time,
        rule_path=rule.rule_path,
        ruleid=as_str(rule.yaml.get("id")) or "-",
        ruletitle=as_str(rule.yaml.get("title")) or "-",
        ruleauthor=as_str(rule.yaml.get("author")) or "-",
        level=level,
        computername=computer_name,
        eventid=eid,
        rec_id=rec_id,
        detail="",
        output_fields=[(column.name, column.kind, column.literal) for column in config.profiles],
    )
    return create_message(record, details, detect_info, converter, False, config.json_timeline, alias, map_key, config)


def _join_agg_values(infos: list[AggRecordTimeInfo], extract: Any) -> str:
    return SEP.join(sorted({extract(info) for info in infos}))


def create_count_output(rule: RuleNode, agg: AggResult) -> str:
    condition = rule.get_agg_condition()
    assert condition is not None
    out = f"Count:{agg.data}"
    if condition.field_name is not None:
        out += f"{SEP}{condition.field_name}:{'/'.join(sorted(agg.field_values))}"
    if condition.by_field_name is not None:
        by_name = condition.by_field_name
        if "," in by_name:
            names = by_name.split(",")
            values = agg.key.split(",")
            out += SEP + SEP.join(f"{name}:{value}" for name, value in zip(names, values, strict=False))
        else:
            out += f"{SEP}{by_name}:{agg.key}"
    return out


def create_agg_log_record(detection: Detection, config: OutputConfig, alias: EventKeyAlias) -> DetectInfo:
    """``Detection::create_agg_log_record``."""
    rule = detection.rule
    agg = detection.agg_result
    assert agg is not None
    tag_info = get_tag_info(rule, config)
    output = create_count_output(rule, agg)
    level = level_index(as_str(rule.yaml.get("level")) or "-")
    computers = _join_agg_values(agg.agg_record_time_info, lambda x: x.computer)
    tactics, techniques, others = _tag_columns(tag_info, config)
    converter: dict[str, tuple[str, str]] = {}
    for column in config.profiles:
        kind = column.kind
        if kind == "Timestamp":
            converter[column.name] = (kind, format_time(agg.start_datetime, False, config.time_format))
        elif kind == "Computer":
            converter[column.name] = (kind, computers)
        elif kind == "Channel":
            converter[column.name] = (kind, _join_agg_values(agg.agg_record_time_info, lambda x: _channel_display(x.channel, config)))
        elif kind == "Level":
            level = level_convert(level, computers, config.critical_systems)
            converter[column.name] = (kind, _level_text(level, config))
        elif kind == "EventID":
            converter[column.name] = (kind, _join_agg_values(agg.agg_record_time_info, lambda x: x.event_id))
        elif kind == "RecordID":
            converter[column.name] = (kind, "")
        elif kind == "EvtxFile":
            converter[column.name] = (kind, _join_agg_values(agg.agg_record_time_info, lambda x: x.evtx_file_path))
        elif kind == "MitreTactics":
            converter[column.name] = (kind, tactics)
        elif kind == "MitreTags":
            converter[column.name] = (kind, techniques)
        elif kind == "OtherTags":
            converter[column.name] = (kind, others)
        elif kind == "Provider":
            converter[column.name] = (kind, "-")
        elif kind == "RecoveredRecord":
            converter["RecoveredRecord"] = ("RenderedMessage", "")
        elif kind == "RenderedMessage":
            converter[column.name] = (kind, "-")
        elif kind in GEOIP_KINDS:
            prefix = kind[:3]
            for suffix in ("ASN", "Country", "City"):
                converter.setdefault(prefix + suffix, (prefix + suffix, "-"))
        else:
            _rule_meta(rule, column, converter)
    detect_info = DetectInfo(
        detected_time=agg.start_datetime,
        rule_path=rule.rule_path,
        ruleid=as_str(rule.yaml.get("id")) or "-",
        ruletitle=as_str(rule.yaml.get("title")) or "-",
        ruleauthor=as_str(rule.yaml.get("author")) or "-",
        level=level,
        computername="-",
        eventid="-",
        rec_id="-",
        detail=output,
        output_fields=[(column.name, column.kind, column.literal) for column in config.profiles],
        agg_result=agg,
    )
    return create_message({}, output, detect_info, converter, True, config.json_timeline, alias, ("", ""), config)


def render(detection: Detection, config: OutputConfig, alias: EventKeyAlias) -> DetectInfo:
    if detection.agg_result is not None:
        return create_agg_log_record(detection, config, alias)
    return create_log_record(detection, config, alias)
