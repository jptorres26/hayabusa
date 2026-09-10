"""Port of the ``mod tests`` block of ``src/detections/field_extract.rs`` (lines 79-188)."""

from __future__ import annotations

import copy
import json

from hayabusa_py.evtx.record import extract_fields


# field_extract.rs:85-120
def test_powershell_classic_data_fields_extraction_400() -> None:
    record_json_str = r"""
{
    "Event": {
        "System": {
            "EventID": 400,
            "Channel": "Windows PowerShell"
        },
        "EventData": {
            "Data": [
                "Available",
                "None",
                "NewEngineState=Available"
            ]
        }
    }
}"""

    val = json.loads(record_json_str)
    key2values: dict[str, str] = {}
    extract_fields("Windows PowerShell", "400", val, key2values)
    extracted_fields = val["Event"]["EventData"]["NewEngineState"]
    assert extracted_fields == "Available"


# field_extract.rs:122-157
def test_powershell_classic_data_fields_extraction_800() -> None:
    record_json_str = r"""
{
    "Event": {
        "System": {
            "EventID": 800,
            "Channel": "Windows PowerShell"
        },
        "EventData": {
            "Data": [
                "Available",
                "NewEngineState=Available",
                "None"
            ]
        }
    }
}"""

    val = json.loads(record_json_str)
    key2values: dict[str, str] = {}
    extract_fields("Windows PowerShell", "800", val, key2values)
    extracted_fields = val["Event"]["EventData"]["NewEngineState"]
    assert extracted_fields == "Available"


# field_extract.rs:159-187
def test_powershell_classic_data_fields_extraction_400_data_2_missing() -> None:
    record_json_str = r"""
{
    "Event": {
        "System": {
            "EventID": 400,
            "Channel": "Windows PowerShell"
        },
        "EventData": {
            "Data": [
                "Available",
                "None"
            ]
        }
    }
}"""

    original_val = json.loads(record_json_str)
    val = copy.deepcopy(original_val)
    key2values: dict[str, str] = {}
    extract_fields("Windows PowerShell", "400", val, key2values)
    assert original_val == val
