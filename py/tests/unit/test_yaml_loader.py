"""Port of the ``mod tests`` block of ``src/yaml.rs`` (lines 948-1554).

The Rust helper ``create_dummy_stored_static`` builds a ``StoredStatic`` for ``dfir-timeline`` with
``min_level: informational``, ``include_status: ["*"]`` and ``config: ./rules/config``; here that
is :class:`RuleFilterOptions` plus the exclude/noisy lists of ``tests/fixtures/config``
(``filter::exclude_ids``).  ``read_dir(path, min_level, exact_level, exclude_ids, ..)`` maps to
``load_rules(path, options, exclude_ids)`` with the two levels carried in the options.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml as pyyaml
from helpers_rules import CONFIG_DIR, TEST_FILES_DIR

from hayabusa_py.rules import yaml12
from hayabusa_py.rules.config import RuleExclude
from hayabusa_py.rules.loader import (
    LoadedRules,
    RuleFilterOptions,
    check_hayabusa_rule_fmt,
    load_rules,
    read_rule_file,
)

RULES_DIR = TEST_FILES_DIR / "rules"


def dummy_options(**overrides: object) -> RuleFilterOptions:
    """yaml.rs:968-984 (the filter-relevant part of ``create_dummy_stored_static``)."""
    options = RuleFilterOptions(min_level="informational", include_status={"*"})
    for key, value in overrides.items():
        setattr(options, key, value)
    return options


def exclude_ids() -> RuleExclude:
    """``filter::exclude_ids(&dummy_stored_static)`` with ``rules/config`` -> the fixture config."""
    return RuleExclude.load(CONFIG_DIR)


def read_dir(path: str | Path, min_level: str, exact_level: str, ids: RuleExclude, options: RuleFilterOptions | None = None) -> LoadedRules:
    """``ParseYaml::read_dir(path, min_level, target_level, exclude_ids, stored_static)``."""
    options = options or dummy_options()
    options.min_level = min_level
    options.exact_level = exact_level
    return load_rules(path, options, ids)


# yaml.rs:986-999
def test_read_file_yaml() -> None:
    ids = RuleExclude()
    loaded = read_dir(RULES_DIR / "yaml" / "1.yml", "", "", ids)
    assert len(loaded.files) == 1


# yaml.rs:1001-1016
def test_read_dir_yaml() -> None:
    ids = RuleExclude(excluded_rule_sources={})
    loaded = read_dir(RULES_DIR / "yaml", "", "", ids)
    assert len(loaded.files) != 0


# yaml.rs:1018-1037
def test_read_yaml() -> None:
    path = RULES_DIR / "yaml" / "1.yml"
    ret = read_rule_file(path)
    rule = list(yaml12.load_all(ret))
    for doc in rule:
        if doc["title"] == "Sysmon Check command lines":
            assert doc["detection"]["selection"]["CommandLine"] == "*"
            assert doc["detection"]["selection"]["EventID"] == 1


# yaml.rs:1039-1045
def test_failed_read_yaml() -> None:
    path = RULES_DIR / "yaml" / "error.yml"
    ret = read_rule_file(path)
    with pytest.raises(pyyaml.YAMLError):
        list(yaml12.load_all(ret))


# yaml.rs:1047-1062
def test_default_level_read_yaml() -> None:
    """When no level argument is specified, the default level (informational) should be applied."""
    loaded = read_dir(RULES_DIR / "level_yaml", "", "", exclude_ids())
    assert len(loaded.files) == 5


# yaml.rs:1064-1078
def test_info_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "INFORMATIONAL", "", exclude_ids())
    assert len(loaded.files) == 5


# yaml.rs:1079-1093
def test_low_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "LOW", "", exclude_ids())
    assert len(loaded.files) == 4


# yaml.rs:1094-1108
def test_medium_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "MEDIUM", "", exclude_ids())
    assert len(loaded.files) == 3


# yaml.rs:1109-1123
def test_high_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "HIGH", "", exclude_ids())
    assert len(loaded.files) == 2


# yaml.rs:1124-1138
def test_critical_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "CRITICAL", "", exclude_ids())
    assert len(loaded.files) == 1


# yaml.rs:1139-1162
def test_all_exclude_rules_file() -> None:
    loaded = read_dir(RULES_DIR / "yaml", "", "", exclude_ids())
    # The excluded fixture rules all use the null-UUID test-rule ID
    # (00000000-0000-0000-0000-000000000000), which must be exempted from the
    # excluded rule count while still being excluded from loading.
    assert loaded.rule_load_cnt["excluded"] == 0
    assert loaded.files
    assert all("exclude" not in filepath for filepath, _ in loaded.files)


# yaml.rs:1164-1186
def test_exclude_rules_file_real_uuid_still_counted() -> None:
    options = dummy_options(include_status={"*"})
    ids = RuleExclude()
    # The real (non-test) rule ID of test_files/rules/yaml/noisy1.yml; the value only
    # needs to contain "exclude_rule" to be classified under the "excluded" counter.
    ids.excluded_rule_sources["0090ea60-f4a2-43a8-8657-3a9a4ddcf547"] = "exclude_rules.txt"
    loaded = read_dir(RULES_DIR / "yaml", "", "", ids, options)
    # A rule with a real UUID must still be counted as excluded and not loaded.
    assert loaded.rule_load_cnt["excluded"] == 1
    assert all("noisy1" not in filepath for filepath, _ in loaded.files)


# yaml.rs:1188-1216
@pytest.mark.skip(reason="yaml::count_rules is the wizard's rule counter (Rust CLI plumbing); no Python equivalent")
def test_count_rules_null_uuid_excluded_not_counted() -> None:
    pass


# yaml.rs:1217-1231
def test_all_noisy_rules_file() -> None:
    loaded = read_dir(RULES_DIR / "yaml", "", "", exclude_ids())
    assert loaded.rule_load_cnt["noisy"] == 5


# yaml.rs:1232-1242
def test_none_exclude_rules_file() -> None:
    options = dummy_options(include_status={"*"})
    ids = RuleExclude()
    loaded = read_dir(RULES_DIR / "yaml", "", "", ids, options)
    assert loaded.rule_load_cnt["excluded"] == 0


# yaml.rs:1243-1256
def test_exclude_deprecated_rules_file() -> None:
    options = dummy_options(include_status={"*"})
    ids = RuleExclude()
    loaded = read_dir(RULES_DIR / "deprecated", "", "", ids, options)
    assert loaded.rule_status_cnt["deprecated"] == 1


# yaml.rs:1258-1271
def test_exclude_unsupported_rules_file() -> None:
    options = dummy_options(include_status={"*"})
    ids = RuleExclude()
    loaded = read_dir(RULES_DIR / "unsupported", "", "", ids, options)
    assert loaded.rule_status_cnt["unsupported"] == 1


# yaml.rs:1273-1287
def test_info_exact_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "", "INFORMATIONAL", exclude_ids())
    assert len(loaded.files) == 1


# yaml.rs:1289-1303
def test_low_exact_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "", "LOW", exclude_ids())
    assert len(loaded.files) == 1


# yaml.rs:1305-1319
def test_medium_exact_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "", "MEDIUM", exclude_ids())
    assert len(loaded.files) == 1


# yaml.rs:1321-1335
def test_high_exact_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "", "HIGH", exclude_ids())
    assert len(loaded.files) == 1


# yaml.rs:1337-1351
def test_critical_exact_level_read_yaml() -> None:
    loaded = read_dir(RULES_DIR / "level_yaml", "", "CRITICAL", exclude_ids())
    assert len(loaded.files) == 1


# yaml.rs:1353-1372
def test_specified_tags_option() -> None:
    options = dummy_options(include_tag=["tag1", "tag2"])
    loaded = read_dir(RULES_DIR / "level_yaml", "", "", exclude_ids(), options)
    assert len(loaded.files) == 3


# yaml.rs:1374-1393
def test_include_category_option_1opt() -> None:
    options = dummy_options(include_category=["test_category1"])
    loaded = read_dir(RULES_DIR / "level_yaml", "", "", exclude_ids(), options)
    assert len(loaded.files) == 1


# yaml.rs:1395-1417
def test_include_category_option_multi_opt() -> None:
    options = dummy_options(include_category=["test_category1", "test_category2"])
    loaded = read_dir(RULES_DIR / "level_yaml", "", "", exclude_ids(), options)
    assert len(loaded.files) == 2


# yaml.rs:1419-1438
def test_include_category_option_not_found() -> None:
    options = dummy_options(include_category=["not found"])
    loaded = read_dir(RULES_DIR / "level_yaml", "", "", exclude_ids(), options)
    assert len(loaded.files) == 0


# yaml.rs:1440-1459
def test_exclude_category_option_1opt() -> None:
    options = dummy_options(exclude_category=["test_category1"])
    loaded = read_dir(RULES_DIR / "level_yaml", "", "", exclude_ids(), options)
    assert len(loaded.files) == 4


# yaml.rs:1461-1483
def test_exclude_category_option_multi_opt() -> None:
    options = dummy_options(exclude_category=["test_category1", "test_category2"])
    loaded = read_dir(RULES_DIR / "level_yaml", "", "", exclude_ids(), options)
    assert len(loaded.files) == 3


# yaml.rs:1485-1504
def test_exclude_category_option_notfound() -> None:
    options = dummy_options(exclude_category=["not found"])
    loaded = read_dir(RULES_DIR / "level_yaml", "", "", exclude_ids(), options)
    assert len(loaded.files) == 5


# yaml.rs:1506-1523
# ``ParseYaml::read_encoded_file`` has no standalone Python counterpart: ``read_rule_file``
# XOR-decodes any file named ``encoded_rules.yml``, so the temporary file is given that name.
def test_read_encoded_file(tmp_path: Path) -> None:
    test_path = tmp_path / "encoded_rules.yml"
    encoded_content = bytes([ord("H") ^ 0xAA, ord("e") ^ 0xAA, ord("l") ^ 0xAA, ord("l") ^ 0xAA, ord("o") ^ 0xAA])
    test_path.write_bytes(encoded_content)
    result = read_rule_file(test_path)
    test_path.unlink()
    assert result == "Hello"


# yaml.rs:1525-1537
def test_read_encoded_file_invalid_utf8_returns_err(tmp_path: Path) -> None:
    # A byte that XOR-decodes (^0xAA) to 0xFF, which is not valid UTF-8. The function must
    # return Err rather than panicking (regression test for #1831).
    test_path = tmp_path / "encoded_rules.yml"
    encoded_content = bytes([0xFF ^ 0xAA])  # decodes to 0xFF
    test_path.write_bytes(encoded_content)
    with pytest.raises(UnicodeDecodeError):
        read_rule_file(test_path)
    test_path.unlink()


# yaml.rs:1539-1553
def test_hayabusa_rule_fmt() -> None:
    directory = RULES_DIR / "level_yaml"
    for path in directory.iterdir():
        read_content = read_rule_file(path)
        yaml_contents = list(yaml12.load_all(read_content))
        for yaml_content in yaml_contents:
            result = check_hayabusa_rule_fmt(yaml_content)
            assert result is None
