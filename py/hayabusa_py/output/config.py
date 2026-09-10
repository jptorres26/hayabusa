"""Output-side configuration: profiles, abbreviations, default details, MITRE tactic names,
critical systems and the field data mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hayabusa_py.engine.timeutil import TimeFormatOptions
from hayabusa_py.engine.values import serde_number_to_string
from hayabusa_py.rules import yaml12
from hayabusa_py.rules.config import load_output_filter_config, read_csv, read_txt
from hayabusa_py.rules.yaml12 import as_i64, as_str

PROFILE_KINDS = {
    "%Timestamp%": "Timestamp",
    "%Computer%": "Computer",
    "%Channel%": "Channel",
    "%Level%": "Level",
    "%EventID%": "EventID",
    "%RecordID%": "RecordID",
    "%RuleTitle%": "RuleTitle",
    "%AllFieldInfo%": "AllFieldInfo",
    "%RuleFile%": "RuleFile",
    "%EvtxFile%": "EvtxFile",
    "%MitreTactics%": "MitreTactics",
    "%MitreTags%": "MitreTags",
    "%OtherTags%": "OtherTags",
    "%RuleAuthor%": "RuleAuthor",
    "%RuleCreationDate%": "RuleCreationDate",
    "%RuleModifiedDate%": "RuleModifiedDate",
    "%Status%": "Status",
    "%RuleID%": "RuleID",
    "%Provider%": "Provider",
    "%Details%": "Details",
    "%RenderedMessage%": "RenderedMessage",
    "%ExtraFieldInfo%": "ExtraFieldInfo",
    "%RecoveredRecord%": "RecoveredRecord",
}
GEOIP_KINDS = {"SrcASN", "SrcCountry", "SrcCity", "TgtASN", "TgtCountry", "TgtCity"}


@dataclass(slots=True)
class ProfileColumn:
    """One output column: its header name and the ``Profile`` variant it renders."""

    name: str
    kind: str  # a PROFILE_KINDS value, a GEOIP kind, or "Literal"
    literal: str = ""  # the fixed text for Literal columns


def load_profile(config_dir: Path, profile_name: str | None) -> list[ProfileColumn]:
    """``profile::load_profile``: columns of ``config/profiles.yaml`` (``-p``) or ``default_profile.yaml``."""
    if profile_name is None:
        docs = list(yaml12.load_all((config_dir / "default_profile.yaml").read_text(encoding="utf-8")))
        table = docs[0] if docs else {}
    else:
        docs = list(yaml12.load_all((config_dir / "profiles.yaml").read_text(encoding="utf-8")))
        profiles = docs[0] if docs else {}
        if profile_name not in profiles:
            raise ValueError(
                f"Invalid profile specified: {profile_name}\nPlease specify one of the following profiles:\n {', '.join(profiles)}"
            )
        table = profiles[profile_name]
    columns = []
    for column_name, alias in table.items():
        alias_text = as_str(alias) or ""
        kind = PROFILE_KINDS.get(alias_text)
        if kind is None:
            columns.append(ProfileColumn(str(column_name), "Literal", alias_text))
        else:
            columns.append(ProfileColumn(str(column_name), kind))
    return columns


def load_default_details(path: Path) -> dict[str, str]:
    """``StoredStatic::get_default_details``: ``Provider_EID`` -> details template."""
    result: dict[str, str] = {}
    try:
        rows = read_csv(path)
    except OSError:
        return result
    for row in rows:
        if len(row) < 3:
            break  # the Rust try_for_each stops at the first malformed line
        provider = row[0].strip()
        try:
            eid = int(row[1].strip())
        except ValueError:
            break
        result[f"{provider}_{eid}"] = row[2].strip()
    return result


class GenericAbbreviator:
    """``generic_abbr_matcher``: ASCII-case-insensitive leftmost-longest replacement of the
    generic_abbreviations.txt originals with their abbreviations."""

    __slots__ = ("_pattern", "_table")

    def __init__(self, table: dict[str, str]) -> None:
        self._table = {key.lower(): value for key, value in table.items()}
        if table:
            alternation = "|".join(re.escape(key) for key in sorted(table, key=len, reverse=True))
            self._pattern: re.Pattern[str] | None = re.compile(alternation, re.IGNORECASE)
        else:
            self._pattern = None

    def replace_all(self, text: str) -> str:
        if self._pattern is None:
            return text
        return self._pattern.sub(lambda match: self._table[match.group(0).lower()], text)


@dataclass(slots=True)
class FieldDataMapKey:
    channel: str = ""
    event_id: str = ""

    def as_tuple(self) -> tuple[str, str]:
        return (self.channel, self.event_id)


@dataclass(slots=True)
class ReplaceStr:
    pattern: re.Pattern[str]
    replacements: dict[str, str]
    providers: set[str]


HEX_TO_DECIMAL = "HexToDecimal"


def build_field_data_map(doc: Any) -> tuple[tuple[str, str], dict[str, Any]]:
    """``field_data_map::build_field_data_map``."""
    if not isinstance(doc, dict):
        return ("", ""), {}
    rewrite = doc.get("RewriteFieldData")
    hex_field = doc.get("HexToDecimal")
    hex_list: list[Any] | None
    if isinstance(hex_field, str):
        hex_list = list(yaml12.load_all(hex_field)) if hex_field else []
        hex_list = [item for sub in hex_list for item in (sub if isinstance(sub, list) else [sub])]
    elif isinstance(hex_field, list):
        hex_list = hex_field
    else:
        hex_list = None
    if not isinstance(rewrite, dict) and hex_list is None:
        return ("", ""), {}
    providers: set[str] = set()
    provider_yaml = doc.get("Provider_Name")
    if isinstance(provider_yaml, list):
        providers = {as_str(p) or "" for p in provider_yaml}
    elif isinstance(provider_yaml, str):
        providers = {provider_yaml}
    mapping: dict[str, Any] = {}
    if isinstance(rewrite, dict):
        for field_name, replace_values in rewrite.items():
            if not isinstance(field_name, str) or not field_name or not isinstance(replace_values, list):
                continue
            table: dict[str, str] = {}
            for entry in replace_values:
                if not isinstance(entry, dict):
                    continue
                for pattern, replacement in entry.items():
                    table[str(pattern) if pattern is not None else ""] = as_str(replacement) or ""
            if not table:
                continue
            # Aho-Corasick default match kind is Standard (leftmost-first over the pattern order,
            # shortest match at a position); patterns are looked up in the original order.
            alternation = "|".join(re.escape(key) for key in table)
            mapping[field_name.lower()] = ReplaceStr(re.compile(alternation), table, providers.copy())
    if hex_list is not None:
        for item in hex_list:
            key = as_str(item)
            if key is not None:
                mapping[key.lower()] = HEX_TO_DECIMAL
    channel = (as_str(doc.get("Channel")) or "").lower()
    event_id = str(as_i64(doc.get("EventID")) or 0)
    return (channel, event_id), mapping


def load_field_data_map(data_mapping_dir: Path) -> dict[tuple[str, str], dict[str, Any]] | None:
    """``field_data_map::create_field_data_map``: None when the directory cannot be read."""
    if not data_mapping_dir.is_dir():
        return None
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in sorted(data_mapping_dir.iterdir()):
        if entry.suffix != ".yaml" or not entry.is_file():
            continue
        try:
            docs = list(yaml12.load_all(entry.read_text(encoding="utf-8", errors="replace")))
        except Exception:
            continue
        for doc in docs:
            key, mapping = build_field_data_map(doc)
            result[key] = mapping
    return result


def convert_field_data(data_map: dict[tuple[str, str], dict[str, Any]] | None, key: tuple[str, str], field_name: str, value: str, record: Any) -> str | None:
    """``field_data_map::convert_field_data``."""
    if data_map is None:
        return None
    entry = data_map.get(key)
    if entry is None:
        return None
    converter = entry.get(field_name)
    if converter is None:
        return None
    if converter == HEX_TO_DECIMAL:
        if value.startswith(("0x", "0X")) and len(value) > 2:
            try:
                return str(int(value[2:], 16))
            except ValueError:
                return value
        return value
    assert isinstance(converter, ReplaceStr)
    if converter.providers:
        provider = ""
        try:
            provider = serde_number_to_string(record["Event"]["System"]["Provider_attributes"]["Name"]) or ""
        except (KeyError, TypeError):
            provider = ""
        if provider not in converter.providers:
            return value
    return converter.pattern.sub(lambda match: converter.replacements[match.group(0)], value)


@dataclass(slots=True)
class OutputConfig:
    """Everything the renderer needs besides the rules (subset of ``StoredStatic``)."""

    profiles: list[ProfileColumn]
    time_format: TimeFormatOptions = field(default_factory=TimeFormatOptions)
    channel_abbr: dict[str, str] = field(default_factory=dict)
    provider_abbr: dict[str, str] = field(default_factory=dict)
    generic_abbr: GenericAbbreviator = field(default_factory=lambda: GenericAbbreviator({}))
    default_details: dict[str, str] = field(default_factory=dict)
    tags_config: dict[str, str] = field(default_factory=dict)  # lowercase tag -> "Abbrev,Html name"
    critical_systems: set[str] = field(default_factory=set)
    field_data_map: dict[tuple[str, str], dict[str, Any]] | None = None
    disable_abbreviation: bool = False
    output_to_file: bool = True
    json_timeline: bool = False
    json_input: bool = False
    include_record_id: bool = False

    @classmethod
    def load(
        cls,
        config_dir: Path,
        rules_config_dir: Path,
        profile_name: str | None = None,
        *,
        time_format: TimeFormatOptions | None = None,
        json_timeline: bool = False,
        disable_abbreviation: bool = False,
        no_field_data_mapping: bool = False,
        output_to_file: bool = True,
    ) -> OutputConfig:
        profiles = load_profile(config_dir, profile_name)
        generic = load_output_filter_config(rules_config_dir / "generic_abbreviations.txt", False, disable_abbreviation)
        tags = load_output_filter_config(config_dir / "mitre_tactics.txt", True, False)
        try:
            critical = {line.strip() for line in read_txt(config_dir / "critical_systems.txt")}
        except OSError:
            critical = set()
        return cls(
            profiles=profiles,
            time_format=time_format or TimeFormatOptions(),
            channel_abbr=load_output_filter_config(rules_config_dir / "channel_abbreviations.txt", True, disable_abbreviation),
            provider_abbr=load_output_filter_config(rules_config_dir / "provider_abbreviations.txt", False, disable_abbreviation),
            generic_abbr=GenericAbbreviator(generic),
            default_details={} if disable_abbreviation else load_default_details(rules_config_dir / "default_details.txt"),
            tags_config=tags,
            critical_systems=critical,
            field_data_map=None if no_field_data_mapping else load_field_data_map(rules_config_dir / "data_mapping"),
            disable_abbreviation=disable_abbreviation,
            output_to_file=output_to_file,
            json_timeline=json_timeline,
            include_record_id=any(column.kind == "RecordID" for column in profiles),
        )
