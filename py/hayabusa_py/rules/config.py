"""Readers for the ``rules/config`` and ``config`` data files (port of parts of
``src/detections/configs.rs``, ``src/filter.rs`` and ``src/detections/utils.rs``).

Everything here is data that ships with Hayabusa/hayabusa-rules and is reused verbatim:
``eventkey_alias.txt``, ``exclude_rules.txt``/``noisy_rules.txt``, ``windash_characters.txt``,
``mitre_tactics.txt``, the abbreviation tables, ``default_details.txt`` and friends.
"""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

IDS_REGEX = re.compile(r"^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$")

# Fallback when rules/config/windash_characters.txt is absent (``configs::load_windash_characters``):
# hyphen, en dash, em dash and horizontal bar are interchangeable for the |windash modifier.
DEFAULT_WINDASH_CHARACTERS = ("-", "–", "—", "―")


def read_txt(path: str | Path) -> list[str]:
    """``utils::read_txt``: the file's lines (no comment handling)."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\r\n") for line in handle]


def parse_csv(contents: str) -> list[list[str]]:
    """``utils::parse_csv``: rows of a CSV whose first row is a header (which is dropped).

    The Rust side uses the ``csv`` crate with default settings (comma delimiter, double-quote
    quoting, flexible row length off -> rows with a different field count are *skipped*).
    """
    reader = csv.reader(io.StringIO(contents))
    rows: list[list[str]] = []
    header_len: int | None = None
    for row in reader:
        if header_len is None:
            header_len = len(row)
            continue
        if len(row) != header_len:
            continue
        rows.append(row)
    return rows


def read_csv(path: str | Path) -> list[list[str]]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return parse_csv(handle.read())


@dataclass(slots=True)
class EventKeyAlias:
    """``configs::EventKeyAliasConfig``: alias -> full dotted event key."""

    key_to_eventkey: dict[str, str] = field(default_factory=dict)

    def get(self, alias: str) -> str | None:
        return self.key_to_eventkey.get(alias)

    @classmethod
    def load(cls, path: str | Path) -> EventKeyAlias:
        """``configs::load_eventkey_alias``: rows are ``alias,event_key``; malformed rows skipped."""
        config = cls()
        try:
            rows = read_csv(path)
        except OSError:
            return config
        for row in rows:
            if len(row) != 2:
                continue
            alias, event_key = row
            if not alias or not event_key:
                continue
            config.key_to_eventkey[alias] = event_key
        return config

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[str, str]]) -> EventKeyAlias:
        return cls(dict(pairs))


@dataclass(slots=True)
class RuleExclude:
    """``filter::RuleExclude``: rule ID -> the list file it came from."""

    excluded_rule_sources: dict[str, str] = field(default_factory=dict)

    def insert_ids(self, filename: str | Path) -> bool:
        """Load one list file; returns False (and changes nothing) when it does not exist."""
        try:
            lines = read_txt(filename)
        except OSError:
            return False
        for line in lines:
            rule_id = line.split("#", 1)[0].strip()
            if not rule_id or not IDS_REGEX.match(rule_id):
                continue
            self.excluded_rule_sources[rule_id] = str(filename)
        return True

    def source_kind(self, rule_id: str) -> str | None:
        """'excluded' / 'noisy' / None, mirroring the ``contains("exclude_rule")`` test in yaml.rs."""
        source = self.excluded_rule_sources.get(rule_id)
        if source is None:
            return None
        return "excluded" if "exclude_rule" in source else "noisy"

    @classmethod
    def load(cls, config_dir: str | Path) -> RuleExclude:
        """``filter::exclude_ids``: noisy_rules.txt then exclude_rules.txt under ``config_dir``."""
        exclude = cls()
        exclude.insert_ids(Path(config_dir) / "noisy_rules.txt")
        exclude.insert_ids(Path(config_dir) / "exclude_rules.txt")
        return exclude


def load_windash_characters(config_dir: str | Path | None) -> tuple[str, ...]:
    """``WINDASH_CHARACTERS``: the first character of every non-empty line of ``windash_characters.txt``."""
    if config_dir is None:
        return DEFAULT_WINDASH_CHARACTERS
    path = Path(config_dir) / "windash_characters.txt"
    try:
        chars = tuple(line[0] for line in read_txt(path) if line)
    except OSError:
        return DEFAULT_WINDASH_CHARACTERS
    return chars


def load_output_filter_config(path: str | Path, is_lower_case: bool, disable_abbreviation: bool = False) -> dict[str, str]:
    """``message::create_output_filter_config``: CSV ``full,abbrev[,extra...]`` -> {full: "abbrev,extra"}."""
    result: dict[str, str] = {}
    if disable_abbreviation:
        return result
    try:
        rows = read_csv(path)
    except OSError:
        return result
    for row in rows:
        if not row:
            continue
        key = row[0].strip().lower() if is_lower_case else row[0].strip()
        result[key] = ",".join(cell.strip() for cell in row[1:])
    return result


def load_expand_map(expand_dir: str | Path | None) -> dict[str, list[str]]:
    """``yaml_expand::read_expand_files``: each ``<name>.txt`` in ``config/expand`` defines the
    placeholder ``%<name>%``; every line (trimmed, empty lines included) is a replacement value.
    Files without any line are ignored."""
    result: dict[str, list[str]] = {}
    if expand_dir is None:
        return result
    directory = Path(expand_dir)
    if not directory.is_dir():
        return result
    for entry in sorted(directory.iterdir()):
        if entry.suffix != ".txt" or not entry.is_file():
            continue
        values = [line.strip() for line in read_txt(entry)]
        if values:
            result[f"%{entry.stem}%"] = values
    return result


@dataclass(slots=True)
class RulesConfig:
    """The subset of ``StoredStatic`` the detection engine needs, loaded from a config directory."""

    eventkey_alias: EventKeyAlias = field(default_factory=EventKeyAlias)
    rule_exclude: RuleExclude = field(default_factory=RuleExclude)
    windash_characters: tuple[str, ...] = DEFAULT_WINDASH_CHARACTERS
    expand_map: dict[str, list[str]] = field(default_factory=dict)
    config_dir: Path | None = None

    @classmethod
    def load(cls, rules_config_dir: str | Path | None, expand_dir: str | Path | None = None) -> RulesConfig:
        if rules_config_dir is None:
            return cls(expand_map=load_expand_map(expand_dir))
        directory = Path(rules_config_dir)
        return cls(
            eventkey_alias=EventKeyAlias.load(directory / "eventkey_alias.txt"),
            rule_exclude=RuleExclude.load(directory),
            windash_characters=load_windash_characters(directory),
            expand_map=load_expand_map(expand_dir),
            config_dir=directory,
        )
