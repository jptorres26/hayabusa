"""Shared helpers for the rule/condition/count tests ported from the Rust ``mod tests`` blocks.

They mirror the Rust test-module helpers (``create_dummy_stored_static``, ``parse_rule_from_str``,
``check_select``, ``check_rule_parse_error``) of ``src/detections/rule/{condition_parser,rulenode,
count}.rs``. The Rust helpers build a ``StoredStatic`` whose ``eventkey_alias`` comes from
``rules/config/eventkey_alias.txt``; here the upstream alias table lives in
``tests/fixtures/config/eventkey_alias.txt``.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

from hayabusa_py.engine.matchers import MatcherContext
from hayabusa_py.engine.rule import RuleNode, get_detection_keys
from hayabusa_py.evtx.record import RecordInfo, create_rec_info
from hayabusa_py.rules import yaml12
from hayabusa_py.rules.config import EventKeyAlias

TESTS_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
CONFIG_DIR = FIXTURES_DIR / "config"
# The Rust tests run from the repository root and reference ``test_files/rules/...``.
REPO_ROOT = TESTS_DIR.parent.parent
TEST_FILES_DIR = REPO_ROOT / "test_files"

TEST_PATH = "testpath"


@cache
def dummy_eventkey_alias() -> EventKeyAlias:
    """``create_dummy_stored_static().eventkey_alias``."""
    alias = EventKeyAlias.load(CONFIG_DIR / "eventkey_alias.txt")
    assert alias.get("EventID") == "Event.System.EventID", "eventkey_alias.txt fixture is missing"
    return alias


def dummy_context() -> MatcherContext:
    """The matcher-relevant part of ``create_dummy_stored_static()``."""
    return MatcherContext()


def create_rule(rule_str: str, rule_path: str = TEST_PATH) -> RuleNode:
    """``create_rule("testpath", YamlLoader::load_from_str(rule_str)[0])`` (not yet initialized)."""
    doc = yaml12.load(rule_str)
    return RuleNode(rule_path, doc)


def init_rule(rule_str: str, rule_path: str = TEST_PATH) -> tuple[RuleNode, list[str]]:
    """Create the rule and run ``init``; returns ``(rule, errors)`` (``Ok(())`` <=> ``errors == []``)."""
    rule = create_rule(rule_str, rule_path)
    errors = rule.init(dummy_context())
    return rule, errors


def parse_rule_from_str(rule_str: str) -> RuleNode:
    """``rulenode::tests::parse_rule_from_str``: create + init, asserting the init succeeded."""
    rule, errors = init_rule(rule_str)
    assert errors == [], f"rule init failed: {errors}"
    return rule


def make_rec_info(rule: RuleNode, record_str: str) -> RecordInfo:
    """``utils::create_rec_info(serde_json::from_str(record_str), "testpath", get_detection_keys(rule), ...)``."""
    try:
        record = json.loads(record_str)
    except json.JSONDecodeError as error:  # the Rust helpers panic here
        raise AssertionError("Failed to parse json record.") from error
    return create_rec_info(record, TEST_PATH, get_detection_keys(rule), dummy_eventkey_alias())


def select_record(rule: RuleNode, record_str: str) -> bool:
    """``rule_node.select(&recinfo, verbose, quiet_errors, json_input, &eventkey_alias, &error_log_stack)``."""
    return rule.select(make_rec_info(rule, record_str), dummy_eventkey_alias())


def check_select(rule_str: str, record_str: str, expect_select: bool) -> None:
    """``check_select`` of condition_parser.rs / rulenode.rs."""
    rule = parse_rule_from_str(rule_str)
    assert select_record(rule, record_str) == expect_select


def check_rule_parse_error(rule_str: str, errmsgs: list[str]) -> None:
    """``check_rule_parse_error`` of condition_parser.rs: ``rule_node.init(..) == Err(errmsgs)``."""
    _rule, errors = init_rule(rule_str)
    assert errors == errmsgs
