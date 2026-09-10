"""CSV / JSON / JSONL timeline writers (port of ``src/results/json.rs``, ``src/results/csv.rs``
and the sorting/deduplication in ``src/results/mod.rs``)."""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable
from typing import Any, TextIO

from hayabusa_py.output.render import SEP, DetectInfo

_I64_RE = re.compile(r"^[-+]?[0-9]+$")
_I64_MIN, _I64_MAX = -(2**63), 2**63 - 1
_DETAIL_KINDS = {"Details", "AllFieldInfo", "ExtraFieldInfo"}
_TAG_KINDS = {"MitreTactics", "MitreTags", "OtherTags"}
_GEOIP_KEYS = ["SrcASN", "SrcCountry", "SrcCity", "TgtASN", "TgtCountry", "TgtCity"]


def close_unterminated_quote(value: str) -> str:
    if value.startswith('"') and not value.endswith('"'):
        return value + '"'
    return value


def json_scalar(value: str) -> Any:
    """``json::json_scalar``: i64 -> number, true/false -> bool, else string."""
    if _I64_RE.match(value):
        number = int(value)
        if _I64_MIN <= number <= _I64_MAX:
            return number
    if value == "true":
        return True
    if value == "false":
        return False
    return close_unterminated_quote(value)


def _json_vec(kind: str, value: str) -> list[str]:
    if kind in _TAG_KINDS:
        return value.split(": ")
    if kind in _DETAIL_KINDS:
        parts = value.split(SEP)
        if value == parts[0] and ": " not in value:
            return []
        return parts
    return []


def _group_details(stock: list[str]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for contents in stock:
        if ":" in contents:
            key, value = contents.split(":", 1)
        else:
            key, value = "", ""
        grouped.setdefault(key.strip(), []).append(value.strip())
    return grouped


def _dumps(value: Any, pretty: bool) -> str:
    if pretty:
        return json.dumps(value, ensure_ascii=False, indent=4)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def output_json_body(info: DetectInfo, jsonl: bool, is_included_geo_ip: bool = False) -> str:
    """``json::output_json_str`` without duplicate-data suppression: the object body (no braces)."""
    record: dict[str, Any] = {}
    field_map = {column: value for column, _, value in info.output_fields}
    valid_geo = [key for key in _GEOIP_KEYS if key in field_map and field_map[key] != "-"]
    for column, kind, value in info.output_fields:
        if kind not in ("AllFieldInfo", "ExtraFieldInfo") and value == "":
            continue
        vec_data = _json_vec(kind, value)
        if column not in _GEOIP_KEYS and kind not in ("AllFieldInfo", "ExtraFieldInfo") and not vec_data:
            if kind == "Details" and value == "-":
                record[column] = {}
                continue
            parts = value.split(": ")
            joined = value if len(parts) == 1 else ": ".join(parts[1:])
            record[column] = json_scalar(joined.strip())
            continue
        if kind in ("SrcASN", "SrcCountry", "SrcCity", "TgtASN", "TgtCountry", "TgtCity"):
            continue
        if kind == "RecoveredRecord":
            record["RecoveredRecord"] = json_scalar(value)
        elif kind in _DETAIL_KINDS:
            stock = info.details_convert_map.get(f"#{kind}")
            if stock is None:
                continue
            if info.agg_result is not None:
                if not stock or stock[0] == "-":
                    record[column] = {}
                    continue
                grouped = _group_details(stock[0].split(SEP))
            elif not stock:
                record[column] = {}
                continue
            else:
                grouped = _group_details(stock)
            details_obj: dict[str, Any] = {}
            for c_key, c_vals in grouped.items():
                if len(c_vals) == 1:
                    details_obj[c_key] = json_scalar(c_vals[0])
                else:
                    details_obj[c_key] = [close_unterminated_quote(v) for v in c_vals]
            if is_included_geo_ip and kind != "ExtraFieldInfo":
                for target in valid_geo:
                    details_obj[target] = json_scalar(field_map[target])
            record[column] = details_obj
        elif kind in _TAG_KINDS:
            values = [part for part in value.split(": ") if part.strip() != ""]
            if not values:
                continue
            record[column] = [close_unterminated_quote(part.strip()) for tag in values for part in tag.split("¦")]
    if not record:
        return ""
    text = _dumps(record, pretty=not jsonl)
    if jsonl:
        return text[1:-1]
    return text[len("{\n") : -len("\n}")]


def write_jsonl(handle: TextIO, infos: Iterable[DetectInfo]) -> None:
    first = True
    for info in infos:
        if not first:
            handle.write("\n")
        first = False
        handle.write("{ " + output_json_body(info, True) + " }")


def write_json(handle: TextIO, infos: Iterable[DetectInfo]) -> None:
    first = True
    for info in infos:
        if not first:
            handle.write("\n")
        first = False
        handle.write("{\n" + output_json_body(info, False) + "\n}")


_CONTROL_RE = re.compile(r"[\n\r\t]")


def _csv_cell(kind: str, value: str, multiline: bool, tab: bool) -> str:
    collapsed = " ".join(value.split())
    if kind == "RuleAuthor" and (multiline or tab):
        sep = "\r\n" if multiline else "\t"
        return sep.join(" ".join(author.split()) for author in re.split(r"[,/;]", value))
    if multiline:
        collapsed = collapsed.replace(SEP, "\r\n")
    elif tab:
        collapsed = collapsed.replace(SEP, "\t")
    return _CONTROL_RE.sub(" ", collapsed) if not (multiline or tab) else collapsed


class _NonNumericDialect(csv.Dialect):
    delimiter = ","
    quotechar = '"'
    doublequote = True
    escapechar = None
    lineterminator = "\n"
    quoting = csv.QUOTE_NONNUMERIC
    skipinitialspace = False


_RUST_F64_RE = re.compile(r"^[+-]?(?:(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|inf|infinity|nan)$", re.IGNORECASE)


def _is_numeric(text: str) -> bool:
    """The csv crate's QuoteStyle::NonNumeric leaves fields that parse as i64 or f64 unquoted."""
    return bool(_I64_RE.match(text)) or bool(_RUST_F64_RE.match(text))


def _csv_row(cells: list[str]) -> str:
    out = []
    for cell in cells:
        if _is_numeric(cell):
            out.append(cell)
        else:
            out.append('"' + cell.replace('"', '""') + '"')
    return ",".join(out) + "\n"


def write_csv(handle: TextIO, infos: Iterable[DetectInfo], *, multiline: bool = False, tab: bool = False) -> None:
    header_written = False
    for info in infos:
        if not header_written:
            handle.write(_csv_row([column.strip() for column, _, _ in info.output_fields]))
            header_written = True
        handle.write(_csv_row([_csv_cell(kind, value, multiline, tab) for _, kind, value in info.output_fields]))


def sort_key(info: DetectInfo) -> tuple:
    """``results::sort_detect_info`` ordering."""
    return (
        info.detected_time,
        info.level,
        info.eventid,
        info.rule_path,
        info.computername,
        info.rec_id,
        tuple(value for _, _, value in info.output_fields),
    )


def duplicate_indices(infos: list[DetectInfo]) -> set[int]:
    """``results::get_duplicate_indices``: later identical rows (EvtxFile ignored) per timestamp."""
    duplicates: set[int] = set()
    seen: set[tuple] = set()
    for index, info in enumerate(infos):
        if index > 0 and infos[index - 1].detected_time != info.detected_time:
            seen.clear()
        fields = tuple((column, kind, value) for column, kind, value in info.output_fields if kind != "EvtxFile")
        if fields in seen:
            duplicates.add(index)
        else:
            seen.add(fields)
    return duplicates


def render_to_string(infos: list[DetectInfo], fmt: str) -> str:
    buffer = io.StringIO()
    if fmt == "jsonl":
        write_jsonl(buffer, infos)
    elif fmt == "json":
        write_json(buffer, infos)
    else:
        write_csv(buffer, infos)
    return buffer.getvalue()
