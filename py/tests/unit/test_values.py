"""Port of the value/time-related tests of the ``mod tests`` block of ``src/detections/utils.rs``
(lines 935-1409).

Only the tests whose subject has a Python counterpart are ported: ``parse_evtx_timestamp`` (->
``timeutil.parse_rfc3339_ns``) and ``get_serde_number_to_string`` (-> ``values.serde_number_to_string``).
The remaining tests exercise Rust CLI plumbing with no equivalent in ``hayabusa_py`` and are not
ported: ``test_read_json_open_error_includes_path``, ``test_json_array_file_to_serde_json_value``,
``test_jsonl_file_to_serde_json_value``, ``test_jq_c_file_to_serde_json_value`` (JSON input readers),
``test_check_setting_path``, ``test_check_setting_path_geoip_yaml_extension`` (config file paths),
``test_check_regex``, ``test_check_allowlist`` (regex list files), ``test_make_ascii_titlecase``,
``test_is_filtered_by_computer_name``, ``test_output_duration`` and ``test_output_profile`` (HTML
report output).
"""

from __future__ import annotations

import json

import pytest

from hayabusa_py.engine.timeutil import parse_rfc3339_ns
from hayabusa_py.engine.values import serde_number_to_string


def utc(text: str) -> int:
    """``Utc.with_ymd_and_hms(...)`` expressed as epoch nanoseconds."""
    value = parse_rfc3339_ns(text)
    assert value is not None
    return value


# utils.rs:1001-1023
def test_parse_evtx_timestamp_applies_offset() -> None:
    """#1820: `parse_evtx_timestamp` must apply the Splunk-JSON UTC offset instead of discarding it."""
    # evtx UTC format ("...Z") is stored as-is.
    assert parse_rfc3339_ns("2021-12-23T00:00:00.000Z") == utc("2021-12-23T00:00:00Z")
    # Splunk JSON "+09:00": the same instant is 9 hours earlier in UTC (previously stored as
    # 00:00:00Z, skewing First/Last Timestamp by 9 hours).
    assert parse_rfc3339_ns("2021-12-23T00:00:00.000+09:00") == utc("2021-12-22T15:00:00Z")
    # A negative offset is applied too.
    assert parse_rfc3339_ns("2021-12-23T00:00:00.000-05:00") == utc("2021-12-23T05:00:00Z")
    assert parse_rfc3339_ns("not a timestamp") is None


# utils.rs:1025-1049
@pytest.mark.skip(reason="utils::create_recordinfos (the %AllFieldInfo% details text) has no Python equivalent yet")
def test_create_recordinfos() -> None:
    pass


# utils.rs:1051-1085
@pytest.mark.skip(reason="utils::create_recordinfos (the %AllFieldInfo% details text) has no Python equivalent yet")
def test_create_recordinfos2() -> None:
    pass


# utils.rs:1117-1135
def test_get_serde_number_to_string() -> None:
    """Numeric type values of Serde::Value are returned as strings."""
    json_str = r"""
        {
            "Event": {
                "System": {
                    "EventID": 11111
                }
            }
        }
        """
    event_record = json.loads(json_str)

    assert serde_number_to_string(event_record["Event"]["System"]["EventID"], False) == "11111"


# utils.rs:1137-1159
def test_get_serde_number_serde_string_to_string() -> None:
    """String type values of Serde::Value are returned as strings."""
    json_str = r"""
        {
            "Event": {
                "EventData": {
                    "ComputerName": "HayabusaComputer1"
                }
            }
        }
        """
    event_record = json.loads(json_str)

    assert serde_number_to_string(event_record["Event"]["EventData"]["ComputerName"], False) == "HayabusaComputer1"


# utils.rs:1161-1178
def test_get_serde_number_serde_object_ret_none() -> None:
    """None is returned when object type contents of Serde::Value are incorrectly passed."""
    json_str = r"""
        {
            "Event": {
                "EventData": {
                    "ComputerName": "HayabusaComputer1"
                }
            }
        }
        """
    event_record = json.loads(json_str)

    assert serde_number_to_string(event_record["Event"]["EventData"], False) is None
