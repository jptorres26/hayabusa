"""Port of the ``mod tests`` block of ``src/yaml_expand.rs`` (lines 137-201)."""

from __future__ import annotations

from hayabusa_py.rules import yaml12
from hayabusa_py.rules.loader import _process_value, process_yaml


# yaml_expand.rs:142-176
def test_process_yaml() -> None:
    yaml_str = r"""
        key1: value1
        key2|expand: "test%placeholder%"
        key3:
          subkey1|expand: "%placeholder%"
          subkey2: subvalue2
        key4|expand:
          - item1
        """

    doc = yaml12.load(yaml_str)
    replacements = {"%placeholder%": ["replace_value1", "replace_value2"]}
    state = [False, False]  # [expand_found, expand_enabled]
    processed_yaml = process_yaml(doc, replacements, state)

    expected_yaml_str = r"""
        key1: value1
        key2: [testreplace_value1, testreplace_value2]
        key3:
          subkey1: [replace_value1, replace_value2]
          subkey2: subvalue2
        key4:
          - item1
        """

    expected_doc = yaml12.load(expected_yaml_str)
    assert state[0]  # expand_found
    assert processed_yaml == expected_doc


# yaml_expand.rs:178-200
def test_process_value() -> None:
    yaml_str = r"""
        key2|expand: "test%placeholder%"
        """

    doc = yaml12.load(yaml_str)
    replacements = {"%placeholder%": ["replace_value1", "replace_value2"]}

    # Test process_value directly
    value = doc["key2|expand"]
    processed_value = _process_value(value, replacements, [False, False])

    expected_value = ["testreplace_value1", "testreplace_value2"]
    assert processed_value == expected_value
