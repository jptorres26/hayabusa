"""Rule discovery, validation and filtering (port of ``src/yaml.rs`` and ``src/yaml_expand.rs``)."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hayabusa_py.rules import yaml12
from hayabusa_py.rules.config import RuleExclude
from hayabusa_py.rules.yaml12 import as_str

DATE_REGEX = re.compile(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}$")
TEST_RULE_ID = "00000000-0000-0000-0000-000000000000"

LEVELS = ["informational", "low", "medium", "high", "critical", "emergency"]
_LEVEL_INDEX = {level: index + 1 for index, level in enumerate(LEVELS)}  # UNDEFINED = 0


def level_index(level: str) -> int:
    """``LEVEL::from(..).index()``: informational=1 .. emergency=6, unknown=0."""
    return _LEVEL_INDEX.get(level.lower(), 0)


Logger = Callable[[str], None] | None


@dataclass(slots=True)
class RuleFilterOptions:
    """The rule-loading options of ``dfir-timeline`` (subset of ``OutputOption``)."""

    min_level: str = "informational"
    exact_level: str = ""
    include_status: set[str] = field(default_factory=lambda: {"*"})
    exclude_status: set[str] = field(default_factory=set)
    enable_deprecated_rules: bool = False
    enable_unsupported_rules: bool = False
    enable_noisy_rules: bool = False
    include_category: list[str] = field(default_factory=list)
    exclude_category: list[str] = field(default_factory=list)
    include_tag: list[str] | None = None
    exclude_tag: list[str] | None = None
    proven_rule_ids: set[str] | None = None  # -P/--proven-rules
    needs_status: bool = True  # dfir-timeline / pivot-keywords-list exclude status-less rules
    verbose: bool = False


def check_hayabusa_rule_fmt(yaml: Any) -> str | None:
    """``yaml::check_hayabusa_rule_fmt``: None when valid, else the joined error text."""
    required = ["author", "title", "logsource", "detection", "level", "status", "date", "id"]
    if isinstance(yaml, dict) and isinstance(yaml.get("correlation"), dict):
        required = [key for key in required if key not in ("logsource", "detection")]
    errors: list[str] = []
    if not isinstance(yaml, dict):
        return " ¦ ".join(f"Missing: {key}" for key in required)
    for key in required:
        if key in yaml:
            value = yaml[key]
            if key == "level":
                if (as_str(value) or "") not in ("informational", "low", "medium", "high", "critical"):
                    errors.append("Invalid: level")
            elif key == "status":
                if (as_str(value) or "") not in ("stable", "test", "experimental", "deprecated", "unsupported"):
                    errors.append("Invalid: status")
            elif key == "date":
                if not DATE_REGEX.match(as_str(value) or ""):
                    errors.append("Invalid: date")
        else:
            errors.append(f"Missing: {key}")
    return " ¦ ".join(errors) if errors else None


# --------------------------------------------------------------------------------------------
# |expand (yaml_expand.rs)
# --------------------------------------------------------------------------------------------


def _process_value(value: Any, replacements: dict[str, list[str]], state: list[bool]) -> Any:
    if isinstance(value, str) and not isinstance(value, yaml12.YamlReal):
        replaced: list[Any] = []
        for placeholder, replace_list in replacements.items():
            if placeholder in value:
                replaced.extend(value.replace(placeholder, replacement) for replacement in replace_list)
        return replaced if replaced else value
    if isinstance(value, list):
        return [process_yaml(item, replacements, state) for item in value]
    return process_yaml(value, replacements, state)


def process_yaml(yaml: Any, replacements: dict[str, list[str]], state: list[bool]) -> Any:
    """``yaml_expand::process_yaml``. ``state`` is ``[expand_found, expand_enabled]``."""
    if isinstance(yaml, dict):
        result: dict[Any, Any] = {}
        for key, value in yaml.items():
            if isinstance(key, str) and "|expand" in key:
                state[0] = True
                new_key = key.replace("|expand", "")
                new_value = _process_value(value, replacements, state)
                if new_value != value:
                    state[1] = True
                result[new_key] = new_value
            else:
                result[key] = process_yaml(value, replacements, state)
        return result
    if isinstance(yaml, list):
        return [process_yaml(item, replacements, state) for item in yaml]
    return yaml


# --------------------------------------------------------------------------------------------
# ParseYaml (yaml.rs)
# --------------------------------------------------------------------------------------------


def read_rule_file(path: Path) -> str:
    """``ParseYaml::read_file`` / ``read_encoded_file`` (XOR 0xAA for ``encoded_rules.yml``)."""
    data = path.read_bytes()
    if path.name == "encoded_rules.yml":
        data = bytes(byte ^ 0xAA for byte in data)
    return data.decode("utf-8")


def iter_rule_files(path: Path) -> Iterable[Path]:
    """Every ``.yml`` under ``path`` (recursively), skipping ``.git`` and the sigmac test files."""
    if path.is_file():
        if path.suffix == ".yml":
            yield path
        return
    for entry in sorted(path.iterdir()):
        if entry.is_dir():
            yield from iter_rule_files(entry)
            continue
        if not entry.is_file() or entry.suffix != ".yml":
            continue
        text = str(entry)
        if "/.git/" in text or "\\.git\\" in text:
            continue
        if "rules/tools/sigmac/test_files" in text or "rules\\tools\\sigmac\\test_files" in text:
            continue
        yield entry


@dataclass(slots=True)
class LoadedRules:
    """``ParseYaml``: the surviving rules plus the counters shown at startup."""

    files: list[tuple[str, Any]] = field(default_factory=list)
    rule_type_cnt: dict[str, int] = field(default_factory=dict)
    rule_load_cnt: dict[str, int] = field(default_factory=lambda: {"excluded": 0, "noisy": 0})
    rule_status_cnt: dict[str, int] = field(default_factory=lambda: {"deprecated": 0, "unsupported": 0})
    rule_cor_cnt: dict[str, int] = field(default_factory=dict)
    rule_cor_ref_cnt: dict[str, int] = field(default_factory=dict)
    rule_expand_cnt: int = 0
    rule_expand_enabled_cnt: int = 0
    error_rule_count: int = 0
    errors: list[str] = field(default_factory=list)

    def _bump(self, counter: dict[str, int], key: str) -> None:
        counter[key] = counter.get(key, 0) + 1


def load_rules(
    rules_path: str | Path,
    options: RuleFilterOptions,
    exclude_ids: RuleExclude,
    expand_map: dict[str, list[str]] | None = None,
    log: Logger = None,
) -> LoadedRules:
    """``ParseYaml::read_dir``: read every rule file, apply all filters, keep the survivors."""
    loaded = LoadedRules()
    expand_map = expand_map or {}
    root = Path(rules_path)

    def warn(message: str) -> None:
        loaded.errors.append(message)
        if log is not None:
            log(message)

    if not root.exists():
        warn(f"[ERROR] fail to read metadata of file: {root}")
        return loaded

    yaml_docs: list[tuple[str, Any]] = []
    for path in iter_rule_files(root):
        try:
            content = read_rule_file(path)
        except (OSError, UnicodeDecodeError) as error:
            warn(f"[WARN] fail to read file: {path}\n{error} ")
            loaded.error_rule_count += 1
            continue
        try:
            documents = list(yaml12.load_all(content))
        except Exception as error:  # yaml.YAMLError and friends
            warn(f"[WARN] Failed to parse yml: {path}\n{error} ")
            loaded.error_rule_count += 1
            continue
        for document in documents:
            if isinstance(document, dict) and isinstance(document.get("correlation"), dict):
                loaded._bump(loaded.rule_cor_cnt, "correlation")
                for ref in document["correlation"].get("rules") or []:
                    if isinstance(ref, str):
                        loaded._bump(loaded.rule_cor_ref_cnt, ref)
            if path.name == "encoded_rules.yml" and isinstance(document, dict):
                filepath = as_str(document.get("rulefile")) or ""
            else:
                filepath = str(path)
            yaml_docs.append((filepath, document))

    all_statuses = "*" in options.include_status
    for filepath, doc in yaml_docs:
        state = [False, False]
        doc = process_yaml(doc, expand_map, state)
        if state[0]:
            loaded.rule_expand_cnt += 1
            if state[1]:
                loaded.rule_expand_enabled_cnt += 1
            else:
                continue
        if not isinstance(doc, dict):
            doc = {}
        rule_id = as_str(doc.get("id"))
        if rule_id is not None:
            kind = exclude_ids.source_kind(rule_id)
            if kind is not None:
                if rule_id != TEST_RULE_ID:
                    loaded._bump(loaded.rule_load_cnt, kind)
                if kind == "excluded" or (kind == "noisy" and not options.enable_noisy_rules):
                    continue
            if options.proven_rule_ids is not None and rule_id not in options.proven_rule_ids:
                loaded._bump(loaded.rule_load_cnt, "excluded")
                continue

        fmt_error = check_hayabusa_rule_fmt(doc)
        if fmt_error is not None:
            warn(f"[WARN] Invalid rule. {fmt_error} ({filepath})")
            loaded.error_rule_count += 1
            continue

        doc_level = (as_str(doc.get("level")) or "informational").upper()
        doc_level_num = level_index(doc_level)
        min_level_num = level_index(options.min_level)
        target_level_num = level_index(options.exact_level) if options.exact_level else 0
        if doc_level_num < min_level_num or (target_level_num != 0 and doc_level_num != target_level_num):
            loaded._bump(loaded.rule_load_cnt, "excluded")
            continue

        status = as_str(doc.get("status"))
        if status is not None:
            if status in options.exclude_status or not (all_statuses or status in options.include_status):
                loaded._bump(loaded.rule_load_cnt, "excluded")
                continue
            if (status == "deprecated" and not options.enable_deprecated_rules) or (
                status == "unsupported" and not options.enable_unsupported_rules
            ):
                loaded._bump(loaded.rule_status_cnt, status)
                continue
        elif not all_statuses and options.needs_status:
            loaded._bump(loaded.rule_load_cnt, "excluded")
            continue

        logsource = doc.get("logsource")
        category = as_str(logsource.get("category")) if isinstance(logsource, dict) else None
        category = category or ""
        if options.include_category and category not in options.include_category:
            loaded._bump(loaded.rule_load_cnt, "excluded")
            continue
        if options.exclude_category and category in options.exclude_category:
            loaded._bump(loaded.rule_load_cnt, "excluded")
            continue

        tags = doc.get("tags")
        tag_list = [as_str(tag) or "" for tag in tags] if isinstance(tags, list) else None
        if options.include_tag is not None:
            if tag_list is None or not any(tag in options.include_tag for tag in tag_list):
                loaded._bump(loaded.rule_load_cnt, "excluded")
                continue
        if options.exclude_tag is not None and tag_list is not None:
            if any(tag in options.exclude_tag for tag in tag_list):
                loaded._bump(loaded.rule_load_cnt, "excluded")
                continue

        loaded._bump(loaded.rule_type_cnt, as_str(doc.get("ruletype")) or "Other")
        loaded._bump(loaded.rule_status_cnt, status or "undefined")
        loaded.files.append((filepath, doc))
    return loaded
