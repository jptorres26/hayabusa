"""Tests for ``hayabusa_py.evtx.xml_record``.

The expectations are the JSON the bundled ``evtx`` crate produces with
``separate_json_attributes(true)`` for the same event, taken from the crate's own
``json_output.rs`` tests and from records in the sample corpus.
"""

from __future__ import annotations

import pytest

from hayabusa_py.evtx.xml_record import guess_scalar, normalize_wevtapi_value, xml_to_record

SECURITY_4624 = """<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>\
<Provider Name="Microsoft-Windows-Security-Auditing" Guid="54849625-5478-4994-A5BA-3E3B0328C30D"></Provider>\
<EventID>4624</EventID><Version>1</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>\
<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2021-12-23T00:00:00.123456Z"></TimeCreated>\
<EventRecordID>1337</EventRecordID><Correlation></Correlation>\
<Execution ProcessID="588" ThreadID="652"></Execution><Channel>Security</Channel>\
<Computer>WIN-77LTAPHIQ1R</Computer><Security></Security></System>\
<EventData><Data Name="TargetUserName">Administrator</Data><Data Name="LogonType">3</Data>\
<Data Name="IpPort">0</Data><Data Name="Empty"></Data></EventData></Event>"""


def test_security_record_layout() -> None:
    record = xml_to_record(SECURITY_4624)
    assert record == {
        "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
        "Event": {
            "System": {
                "Provider_attributes": {
                    "Name": "Microsoft-Windows-Security-Auditing",
                    "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
                },
                "EventID": 4624,
                "Version": 1,
                "Level": 0,
                "Task": 12544,
                "Opcode": 0,
                "Keywords": "0x8020000000000000",
                "TimeCreated_attributes": {"SystemTime": "2021-12-23T00:00:00.123456Z"},
                "EventRecordID": 1337,
                "Correlation": None,
                "Execution_attributes": {"ProcessID": 588, "ThreadID": 652},
                "Channel": "Security",
                "Computer": "WIN-77LTAPHIQ1R",
                "Security": None,
            },
            "EventData": {
                "TargetUserName": "Administrator",
                "LogonType": 3,
                "IpPort": 0,
                "Empty": "",
            },
        },
    }


def test_named_data_keeps_key_order() -> None:
    record = xml_to_record(SECURITY_4624)
    assert list(record["Event"]["EventData"]) == ["TargetUserName", "LogonType", "IpPort", "Empty"]


def test_complexdata_is_keyed_by_name() -> None:
    """Issue #1520: ``<ComplexData Name=...>`` keys by ``Name`` exactly like ``<Data>``."""
    xml = '<Event><EventData><ComplexData Name="Idle">7</ComplexData></EventData></Event>'
    assert xml_to_record(xml)["Event"]["EventData"] == {"Idle": 7}


def test_unnamed_data_elements_become_an_array() -> None:
    xml = "<Event><EventData><Data>a</Data><Data></Data><Data>c</Data></EventData></Event>"
    assert xml_to_record(xml)["Event"]["EventData"] == {"Data": ["a", "", "c"]}


def test_single_unnamed_data_is_a_one_element_array() -> None:
    xml = "<Event><EventData><Data>only</Data></EventData></Event>"
    assert xml_to_record(xml)["Event"]["EventData"] == {"Data": ["only"]}


def test_single_empty_unnamed_data_is_absent() -> None:
    xml = "<Event><EventData><Data></Data></EventData></Event>"
    assert xml_to_record(xml)["Event"]["EventData"] == {"Data": None}


def test_duplicate_keys_get_numbered_slots() -> None:
    """The crate's linear probe: the newest value keeps the bare key."""
    xml = (
        "<Event><UserData><HTTPResponseHeadersInfo>"
        "<Header>HTTP/1.1 200 OK</Header><Header>x-ms-version: 2009-09-19</Header>"
        "</HTTPResponseHeadersInfo></UserData></Event>"
    )
    headers = xml_to_record(xml)["Event"]["UserData"]["HTTPResponseHeadersInfo"]
    assert headers == {"Header": "x-ms-version: 2009-09-19", "Header_1": "HTTP/1.1 200 OK"}


def test_duplicate_keys_with_attributes() -> None:
    xml = (
        "<Event><UserData><HTTPResponseHeadersInfo>"
        '<Header attribute1="NoProxy"></Header><Header>HTTP/1.1 200 OK</Header>'
        "</HTTPResponseHeadersInfo></UserData></Event>"
    )
    headers = xml_to_record(xml)["Event"]["UserData"]["HTTPResponseHeadersInfo"]
    assert headers == {"Header_attributes": {"attribute1": "NoProxy"}, "Header": "HTTP/1.1 200 OK"}


def test_element_with_attributes_and_no_value_drops_the_value_key() -> None:
    xml = '<Event><System><Provider Name="P"></Provider></System></Event>'
    assert xml_to_record(xml)["Event"]["System"] == {"Provider_attributes": {"Name": "P"}}


def test_empty_attribute_values_are_dropped() -> None:
    """``insert_node_with_attributes`` skips attributes whose value is null."""
    xml = '<Event><System><EventID Qualifiers="">4902</EventID></System></Event>'
    assert xml_to_record(xml)["Event"]["System"] == {"EventID": 4902}


def test_userdata_empty_leaf_is_an_empty_string() -> None:
    xml = "<Event><UserData><InstallDeviceID><DriverName></DriverName></InstallDeviceID></UserData></Event>"
    assert xml_to_record(xml)["Event"]["UserData"]["InstallDeviceID"] == {"DriverName": ""}


def test_eventdata_empty_leaf_is_null() -> None:
    xml = "<Event><EventData><Binary></Binary></EventData></Event>"
    assert xml_to_record(xml)["Event"]["EventData"] == {"Binary": None}


def test_carriage_returns_survive() -> None:
    xml = '<Event><EventData><Data Name="Script">a\r\nb</Data></EventData></Event>'
    assert xml_to_record(xml)["Event"]["EventData"]["Script"] == "a\r\nb"


def test_control_characters_survive() -> None:
    xml = '<Event><EventData><Data Name="PrivilegeList">\x94\x02-</Data></EventData></Event>'
    assert xml_to_record(xml)["Event"]["EventData"]["PrivilegeList"] == "\x94\x02-"


def test_pretty_printed_input_drops_the_writers_indentation() -> None:
    xml = '<Event>\n  <EventData>\n    <Data Name="X">v</Data>\n    <Data Name="Y">\n    </Data>\n  </EventData>\n</Event>'
    assert xml_to_record(xml, pretty=True)["Event"]["EventData"] == {"X": "v", "Y": ""}


def test_newline_only_value_is_content() -> None:
    xml = '<Event><EventData><Data Name="ExtraInfo">\n</Data></EventData></Event>'
    assert xml_to_record(xml)["Event"]["EventData"]["ExtraInfo"] == "\n"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("0", 0),
        ("4624", 4624),
        ("-1", -1),
        ("18446744073709551615", 18446744073709551615),
        ("18446744073709551616", "18446744073709551616"),
        ("007", "007"),
        ("+1", "+1"),
        ("0x8020000000000000", "0x8020000000000000"),
        ("true", True),
        ("false", False),
        ("True", "True"),
        ("", ""),
        ("1.5", "1.5"),
    ],
)
def test_guess_scalar(text: str, expected: object) -> None:
    assert guess_scalar(text) == expected
    assert type(guess_scalar(text)) is type(expected)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("{54849625-5478-4994-a5ba-3e3b0328c30d}", "54849625-5478-4994-A5BA-3E3B0328C30D"),
        ("54849625-5478-4994-A5BA-3E3B0328C30D", "54849625-5478-4994-A5BA-3E3B0328C30D"),
        ("2021-12-23T00:00:00.1234567Z", "2021-12-23T00:00:00.123456Z"),
        ("2021-12-23T00:00:00.123456Z", "2021-12-23T00:00:00.123456Z"),
        ("2021-12-23T00:00:00Z", "2021-12-23T00:00:00.000000Z"),
        ("2021-12-23T00:00:00.5Z", "2021-12-23T00:00:00.500000Z"),
        ("not a guid", "not a guid"),
    ],
)
def test_normalize_wevtapi_value(text: str, expected: str) -> None:
    assert normalize_wevtapi_value(text) == expected


def test_wevtapi_mode_normalizes_values_in_place() -> None:
    xml = (
        "<Event><System>"
        '<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"></Provider>'
        '<TimeCreated SystemTime="2021-02-01T11:13:11.1959551Z"></TimeCreated>'
        "</System></Event>"
    )
    system = xml_to_record(xml, wevtapi=True)["Event"]["System"]
    assert system["Provider_attributes"]["Guid"] == "5770385F-C22A-43E0-BF4C-06F5698FFBD9"
    assert system["TimeCreated_attributes"]["SystemTime"] == "2021-02-01T11:13:11.195955Z"
