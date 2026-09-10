"""Port of the ``mod tests`` block of ``src/detections/rule/count.rs`` (lines 621-1983)."""

from __future__ import annotations

from helpers_rules import init_rule, select_record

from hayabusa_py.engine.aggregation import AggResult
from hayabusa_py.engine.rule import RuleNode
from hayabusa_py.engine.timeutil import parse_rfc3339_ns

# count.rs:639-654
SIMPLE_RECORD_STR = r"""
    {
      "Event": {
        "System": {
          "EventID": 7040,
          "Channel": "System"
        },
        "EventData": {
          "param1": "Windows Event Log",
          "param2": "auto start"
        }
      },
      "Event_attributes": {
        "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
      }
    }"""


def utc(text: str) -> int:
    """``Utc.with_ymd_and_hms(...)`` expressed as epoch nanoseconds."""
    value = parse_rfc3339_ns(text)
    assert value is not None
    return value


def agg(data: int, key: str, field_values: list[str], start: str) -> AggResult:
    """``AggResult::new(data, key, field_values, start_datetime, vec![])``."""
    return AggResult(data, key, field_values, utc(start), [])


def _init_and_select(rule_str: str, records: list[str], assert_match: bool) -> RuleNode:
    rule, errors = init_rule(rule_str)
    assert errors == [], "Failed to init rulenode"
    for record_str in records:
        matched = select_record(rule, record_str)
        if assert_match:
            assert matched is True
    return rule


def run_count_select(rule_str: str, record_str: str) -> list[AggResult]:
    """count.rs:816-844: build a rule + record, run ``select()``, assert the record matched."""
    rule = _init_and_select(rule_str, [record_str], assert_match=True)
    return rule.judge_satisfy_aggcondition()


def test_create_recstr_std(event_id: str, time: str) -> str:
    """count.rs:1861-1863"""
    return test_create_recstr(event_id, time, "Windows Event Log")


def test_create_recstr(event_id: str, time: str, param1: str) -> str:
    """count.rs:1865-1884"""
    template = r"""
    {
      "Event": {
        "System": {
          "EventID": ${EVENT_ID},
          "TimeCreated_attributes": {
            "SystemTime": "${TIME}"
          }
        },
        "EventData": {
          "param1": "${PARAM1}"
        }
      }
    }"""
    return template.replace("${EVENT_ID}", event_id).replace("${TIME}", time).replace("${PARAM1}", param1)


# The two ``test_create_recstr*`` helpers above are named like the Rust ones; keep pytest from
# collecting them as tests.
test_create_recstr_std.__test__ = False  # type: ignore[attr-defined]
test_create_recstr.__test__ = False  # type: ignore[attr-defined]


def create_std_rule(count: str, timeframe: str) -> str:
    """count.rs:1886-1899"""
    template = r"""
    enabled: true
    detection:
        selection1:
            param1: 'Windows Event Log'
        condition: selection1 | ${COUNT}
        timeframe: ${TIME_FRAME}
    details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
    """
    return template.replace("${COUNT}", count).replace("${TIME_FRAME}", timeframe)


def check_count(rule_str: str, records_str: list[str], expected_counts: dict[str, int], expect_agg_results: list[AggResult]) -> None:
    """count.rs:1901-1982: run the rule against the records, then assert both the per-key
    countdata sizes and the resulting AggResults against the expected values."""
    rule = _init_and_select(rule_str, records_str, assert_match=True)
    agg_results = rule.judge_satisfy_aggcondition()
    assert len(agg_results) == len(expect_agg_results)

    expect_data = []
    expect_key = []
    expect_field_values = []
    expect_start_timedate = []
    for expect_agg in expect_agg_results:
        expect_count = expected_counts.get(expect_agg.key, -1)
        # Verify that the countup function is working.
        assert len(rule.countdata[expect_agg.key]) == expect_count
        expect_data.append(expect_agg.data)
        expect_key.append(expect_agg.key)
        expect_field_values.append(expect_agg.field_values)
        expect_start_timedate.append(expect_agg.start_datetime)
    for agg_result in agg_results:
        # The lookup doubles as the check that start_datetime was stored correctly:
        # it fails if it is not among the expected values.
        assert agg_result.start_datetime in expect_start_timedate
        index = expect_start_timedate.index(agg_result.start_datetime)
        assert agg_result.data == expect_data[index]
        assert agg_result.key == expect_key[index]
        assert len(agg_result.field_values) == len(expect_field_values[index])
        for expect_field_value in expect_field_values[index]:
            # The order of the field elements does not matter for subsequent processing.
            assert expect_field_value in agg_result.field_values


# count.rs:670-720
def test_count_no_field_and_by() -> None:
    """Rule detection works when count() has no field argument and no `by` clause (without timeframe)."""
    record_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1996-02-27T01:05:01Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 | count() >= 1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """
    expected_count = {"_": 2}
    expected_agg_result = [agg(2, "_", [], "1977-01-01T00:00:00Z")]
    check_count(rule_str, [SIMPLE_RECORD_STR, record_str], expected_count, expected_agg_result)


# count.rs:722-782
def test_count_no_field_and_by_with_timeframe() -> None:
    """Rule detection works when count() has no field argument and no `by` clause (with timeframe)."""
    record_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1996-02-27T01:05:01Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 | count() >= 1
            timeframe: 15m
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """
    expected_count = {"_": 2}
    expected_agg_result = [
        agg(1, "_", [], "1977-01-01T00:00:00Z"),
        agg(1, "_", [], "1996-02-27T01:05:01Z"),
    ]
    check_count(rule_str, [SIMPLE_RECORD_STR, record_str], expected_count, expected_agg_result)


# count.rs:784-814
def test_count_exist_field() -> None:
    """Count detection by rule works when count() has a field argument."""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3 | count(Channel) >= 1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """
    expected_count = {"_": 1}
    expected_agg_result = agg(1, "_", ["System"], "1977-01-01T00:00:00Z")
    check_count(rule_str, [SIMPLE_RECORD_STR], expected_count, [expected_agg_result])


# count.rs:846-863
def test_count_missing_system_fields_no_panic() -> None:
    """Regression: a record that matches the selection but has no `Event.System` object (so the
    EventID/Computer/Channel lookups in `countup()` return `None`) must not panic and abort the scan."""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                param1: 'Windows Event Log'
            condition: selection1 | count() >= 1
        details: 'x'
        """
    # No Event.System -> get_event_value("Event.System.{EventID,Computer,Channel}") is None.
    record_str = r"""{"Event":{"EventData":{"param1":"Windows Event Log"}}}"""
    result = run_count_select(rule_str, record_str)
    assert len(result) == 1  # `count() >= 1` is satisfied, no panic


# count.rs:865-883
def test_count_missing_alias_and_eventid_no_panic() -> None:
    """Regression: the "alias not found" warn-and-continue arm must not panic while formatting its
    diagnostic when the record also lacks an EventID. Here `count(Computer)`'s Computer alias
    resolves through the absent `Event.System`, hitting the None arm, and the EventID it reports is
    likewise absent."""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                param1: 'Windows Event Log'
            condition: selection1 | count(Computer) >= 1
        details: 'x'
        """
    record_str = r"""{"Event":{"EventData":{"param1":"Windows Event Log"}}}"""
    # Must not panic building the "alias not found" diagnostic (EventID is None).
    _agg = run_count_select(rule_str, record_str)


# count.rs:885-942
def test_count_exist_field_and_by() -> None:
    """Count detection by rule works when count() has both a field argument and a `by` clause."""
    record_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 9999,
              "Channel": "Test",
              "TimeCreated_attributes": {
                "SystemTime": "1996-02-27T01:05:01Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                param1: 'Windows Event Log'
            condition: selection1 | count(EventID) by Channel >= 1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """
    expected_count = {"System": 1, "Test": 1}
    expected_agg_result = [
        agg(1, "System", ["7040"], "1977-01-01T00:00:00Z"),
        agg(1, "Test", ["9999"], "1996-02-27T01:05:01Z"),
    ]
    check_count(rule_str, [SIMPLE_RECORD_STR, record_str], expected_count, expected_agg_result)


# count.rs:944-1001
def test_count_exist_field_and_by_with_othervalue_in_timeframe() -> None:
    """When count() has both a field argument and a `by` clause, counting is done separately per
    `by` value (with the count() field values differing across records)."""
    record_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 9999,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1977-01-01T00:05:00Z"
              }
            },
            "EventData": {
              "param1": "Test",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            condition: selection1 | count(EventID) by param1 >= 1
            timeframe: 1h
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """
    expected_count = {"Windows Event Log": 1, "Test": 1}
    expected_agg_result = [
        agg(1, "Windows Event Log", ["7040"], "1977-01-01T00:00:00Z"),
        agg(1, "Test", ["9999"], "1977-01-01T00:05:00Z"),
    ]
    check_count(rule_str, [SIMPLE_RECORD_STR, record_str], expected_count, expected_agg_result)


# count.rs:1003-1072
def test_count_not_satisfy_in_timeframe() -> None:
    """An empty array is returned when the rule's count condition is not satisfied because of the
    timeframe condition."""
    record_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1977-01-01T01:05:00Z"
              }
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            condition: selection1 | count(EventID) >= 2
            timeframe: 1h
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """
    rule = _init_and_select(rule_str, [SIMPLE_RECORD_STR, record_str], assert_match=False)
    # Verify that the countup function is working.
    assert len(rule.countdata["_"]) == 2
    judge_result = rule.judge_satisfy_aggcondition()
    assert len(judge_result) == 0


# count.rs:1073-1166
def test_count_field_timeframe_no_out_of_frame_false_positive() -> None:
    """Regression test for #1811: the sliding window in `judge_timeframe` must not pull a record
    that is outside the timeframe into a window. Two records share EventID 4624 five seconds apart,
    and a third with EventID 4625 arrives ten minutes later. With `count(EventID) >= 2` and a
    one-minute timeframe there is never a one-minute window containing two distinct EventIDs, so no
    alert must be produced."""
    record0 = r"""
        {
          "Event": {
            "System": {
              "EventID": 4624,
              "Channel": "System",
              "TimeCreated_attributes": { "SystemTime": "2021-01-01T00:00:00Z" }
            }
          },
          "Event_attributes": { "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event" }
        }"""
    record1 = r"""
        {
          "Event": {
            "System": {
              "EventID": 4624,
              "Channel": "System",
              "TimeCreated_attributes": { "SystemTime": "2021-01-01T00:00:05Z" }
            }
          },
          "Event_attributes": { "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event" }
        }"""
    record2 = r"""
        {
          "Event": {
            "System": {
              "EventID": 4625,
              "Channel": "System",
              "TimeCreated_attributes": { "SystemTime": "2021-01-01T00:10:00Z" }
            }
          },
          "Event_attributes": { "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event" }
        }"""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            condition: selection1 | count(EventID) >= 2
            timeframe: 1m
        details: 'count field timeframe regression'
        """
    rule = _init_and_select(rule_str, [record0, record1, record2], assert_match=False)
    # All three records match the selection and are counted.
    assert len(rule.countdata["_"]) == 3
    # No one-minute window holds two distinct EventIDs, so there must be no alert.
    judge_result = rule.judge_satisfy_aggcondition()
    assert len(judge_result) == 0


# count.rs:1167-1215
def test_count_exist_field_and_by_with_timeframe() -> None:
    """Count detection by rule works when count() has both a field argument and a `by` clause and
    the records fall within the timeframe."""
    record_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 9999,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1977-01-01T00:05:00Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                param1: 'Windows Event Log'
            condition: selection1 | count(EventID) by Channel >= 2
            timeframe: 30m
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """
    expected_count = {"System": 2}
    expected_agg_result = [agg(2, "System", ["7040", "9999"], "1977-01-01T00:00:00Z")]
    check_count(rule_str, [SIMPLE_RECORD_STR, record_str], expected_count, expected_agg_result)


# count.rs:1217-1267
def test_count_exist_field_and_by_with_timeframe_other_field_value() -> None:
    """Count detection by rule works when count() has both a field argument and a `by` clause and
    the records fall within the timeframe (with differing count() field values)."""
    record_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 9999,
              "Channel": "System",
              "TimeCreated_attributes": {
                "SystemTime": "1977-01-01T00:30:00Z"
              }
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auto start"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                param1: 'Windows Event Log'
            condition: selection1 | count(EventID) by Channel >= 1
            timeframe: 1h
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """
    default_time = "1977-01-01T00:00:00Z"
    expected_count = {"System": 2}
    expected_agg_result = [agg(2, "System", ["7040", "9999"], default_time)]
    check_count(rule_str, [SIMPLE_RECORD_STR, record_str], expected_count, expected_agg_result)


# count.rs:1269-1301
def test_count_timeframe_seconds() -> None:
    # Verify that timeframe seconds work.
    recs = [
        test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T00:30:10Z"),
        test_create_recstr_std("3", "1977-01-09T00:30:20Z"),
    ]

    # timeframe=20s just barely hits.
    rule_str = create_std_rule("count(EventID) >= 3", "20s")
    default_time = "1977-01-09T00:30:00Z"
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=19s just barely does not hit.
    rule_str = create_std_rule("count(EventID) >= 3", "19s")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1303-1335
def test_count_timeframe_minutes() -> None:
    # Verify that timeframe minutes work.
    recs = [
        test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T00:40:00Z"),
        test_create_recstr_std("3", "1977-01-09T00:50:00Z"),
    ]

    # timeframe=20m just barely hits.
    rule_str = create_std_rule("count(EventID) >= 3", "20m")
    default_time = "1977-01-09T00:30:00Z"
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=19m just barely does not hit.
    rule_str = create_std_rule("count(EventID) >= 3", "19m")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1337-1409
def test_count_timeframe_hour() -> None:
    # Verify that timeframe hours work.
    recs = [
        test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T01:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T02:30:00Z"),
    ]
    default_time = "1977-01-09T00:30:00Z"

    # timeframe=3h hits.
    rule_str = create_std_rule("count(EventID) >= 3", "3h")
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=2h just barely hits.
    rule_str = create_std_rule("count(EventID) >= 3", "2h")
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=1h just barely does not hit.
    rule_str = create_std_rule("count(EventID) >= 3", "1h")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])

    # timeframe=120m just barely hits.
    rule_str = create_std_rule("count(EventID) >= 3", "120m")
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=119m just barely does not hit.
    rule_str = create_std_rule("count(EventID) >= 3", "119m")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1411-1443
def test_count_timeframe_day() -> None:
    # Verify that timeframe days work.
    recs = [
        test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
        test_create_recstr_std("2", "1977-01-13T00:30:00Z"),
        test_create_recstr_std("3", "1977-01-20T00:30:00Z"),
    ]

    # timeframe=11d just barely hits.
    rule_str = create_std_rule("count(EventID) >= 3", "11d")
    default_time = "1977-01-09T00:30:00Z"
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=10d just barely does not hit.
    rule_str = create_std_rule("count(EventID) >= 3", "10d")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1445-1477
def test_count_timeframe_milsecs() -> None:
    # evtx timestamps may contain fractional seconds, so verify they are handled correctly.
    recs = [
        test_create_recstr_std("1", "2021-12-21T10:40:00.0000000Z"),
        test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
        test_create_recstr_std("3", "2021-12-21T10:40:10.0003000Z"),
    ]

    # timeframe=11s just barely hits.
    rule_str = create_std_rule("count(EventID) >= 3", "11s")
    default_time = "2021-12-21T10:40:00Z"
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=10s just barely does not hit.
    rule_str = create_std_rule("count(EventID) >= 3", "10s")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1479-1517
def test_count_timeframe_milsecs2() -> None:
    # evtx timestamps may contain fractional seconds, so verify they are handled correctly.
    recs = [
        test_create_recstr_std("1", "2021-12-21T10:40:00.0500000Z"),
        test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
        test_create_recstr_std("3", "2021-12-21T10:40:10.0400000Z"),
    ]

    # timeframe=10s just barely hits.
    rule_str = create_std_rule("count(EventID) >= 3", "10s")
    default_time = "2021-12-21T10:40:00.050Z"
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=9s just barely does not hit.
    rule_str = create_std_rule("count(EventID) >= 3", "9s")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1519-1557
def test_count_timeframe_milsecs3() -> None:
    # evtx timestamps may contain fractional seconds, so verify they are handled correctly.
    recs = [
        test_create_recstr_std("1", "2021-12-21T10:40:00.0500000Z"),
        test_create_recstr_std("2", "2021-12-21T10:40:05.0000000Z"),
        test_create_recstr_std("3", "2021-12-21T10:40:10.0600000Z"),
    ]

    # timeframe=11s just barely hits.
    rule_str = create_std_rule("count(EventID) >= 3", "11s")
    default_time = "2021-12-21T10:40:00.050Z"
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # timeframe=10s just barely does not hit.
    rule_str = create_std_rule("count(EventID) >= 3", "10s")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1559-1569
def test_count_norecord() -> None:
    # Test when there are no hit records.
    recs: list[str] = []

    rule_str = create_std_rule("count(EventID) >= 3", "10s")
    expected_count: dict[str, int] = {}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1571-1619
def test_count_onerecord() -> None:
    # Verify that detection works correctly with 1 record.
    recs = [test_create_recstr_std("1", "2021-12-21T10:40:00.0000000Z")]
    default_time = "2021-12-21T10:40:00.000Z"

    # Without by.
    rule_str = create_std_rule("count(EventID) >= 1", "1s")
    expected_count = {"_": 1}
    expected_agg_result = [agg(1, "_", ["1"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # With by.
    rule_str = create_std_rule("count(EventID) by param1>= 1", "1s")
    expected_count = {"Windows Event Log": 1}
    expected_agg_result = [agg(1, "Windows Event Log", ["1"], default_time)]
    check_count(rule_str, recs, expected_count, expected_agg_result)


# count.rs:1621-1655
def test_count_timeframe1() -> None:
    # Timeframe inspection: timeframe=2h with `count(EventID) >= 3` after the pipe.
    #
    # Here the first 3 rows should not be detected, but rows 2 through 4 should be.
    # Checks the pattern where detection starts in the middle rather than at the first row.
    recs = [
        test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
        test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
        test_create_recstr_std("4", "1977-01-09T10:30:00Z"),
        test_create_recstr_std("5", "1977-01-09T11:30:00Z"),
        test_create_recstr_std("4", "1977-01-09T12:30:00Z"),
    ]
    rule_str = create_std_rule("count(EventID) >= 3", "2h")

    expected_count = {"_": 7}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], "1977-01-09T01:30:00Z")]
    check_count(rule_str, recs, expected_count, expected_agg_result)


# count.rs:1657-1676
def test_count_timeframe2() -> None:
    # Comes close but never detects: every 2h window holds only 2 distinct EventIDs.
    recs = [
        test_create_recstr_std("2", "1977-01-09T01:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T04:30:00Z"),
        test_create_recstr_std("1", "1977-01-09T05:30:00Z"),
        test_create_recstr_std("1", "1977-01-09T06:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T07:30:00Z"),
    ]

    rule_str = create_std_rule("count(EventID) >= 3", "2h")
    expected_count = {"_": 7}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1678-1708
def test_count_sametime() -> None:
    # Can correctly count even when records have the same timestamp.
    recs = [
        test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T01:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T02:30:00Z"),
        test_create_recstr_std("4", "1977-01-09T02:30:00Z"),
    ]

    rule_str = create_std_rule("count(EventID) >= 4", "1h")
    expected_count = {"_": 4}
    expected_agg_result = [agg(4, "_", ["1", "2", "3", "4"], "1977-01-09T01:30:00Z")]
    check_count(rule_str, recs, expected_count, expected_agg_result)


# count.rs:1710-1745
def test_count_sentinel() -> None:
    # The count implementation places no sentinel at the end of the data; check it still works.
    # Verify that no error occurs when the time span of all matching records is narrower than the
    # rule's timeframe.
    recs = [
        test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
    ]

    # Pattern that hits.
    rule_str = create_std_rule("count(EventID) >= 3", "1d")
    expected_count = {"_": 3}
    expected_agg_result = [agg(3, "_", ["1", "2", "3"], "1977-01-09T01:30:00Z")]
    check_count(rule_str, recs, expected_count, expected_agg_result)

    # Pattern that does not hit.
    rule_str = create_std_rule("count(EventID) >= 4", "1d")
    expected_count = {"_": 3}
    check_count(rule_str, recs, expected_count, [])


# count.rs:1747-1812
def test_count_timeframe_reset() -> None:
    # There are 4 distinct EventIDs from 1:30 to 4:30, and likewise 4 from 2:30 to 5:30.
    # Verify that once 4 distinct values are found in 1:30-4:30, counting restarts from 5:30.
    recs = [
        test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T03:30:00Z"),
        test_create_recstr_std("4", "1977-01-09T04:30:00Z"),
        test_create_recstr_std("1", "1977-01-09T05:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T06:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T07:30:00Z"),
        test_create_recstr_std("4", "1977-01-09T08:30:00Z"),
        test_create_recstr_std("1", "1977-01-09T09:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T10:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T11:30:00Z"),
        test_create_recstr_std("4", "1977-01-09T12:30:00Z"),
    ]

    rule_str = create_std_rule("count(EventID) >= 4", "3h")
    expected_count = {"_": len(recs)}
    expected_agg_result = [
        agg(4, "_", ["1", "2", "3", "4"], "1977-01-09T01:30:00Z"),
        agg(4, "_", ["1", "2", "3", "4"], "1977-01-09T05:30:00Z"),
        agg(4, "_", ["1", "2", "3", "4"], "1977-01-09T09:30:00Z"),
    ]
    check_count(rule_str, recs, expected_count, expected_agg_result)


# count.rs:1814-1859
def test_count_timeframe_twice() -> None:
    # Timeframe inspection: timeframe=2h with `count(EventID) >= 3` after the pipe.
    #
    # The test_count_timeframe1() pattern repeated twice.
    recs = [
        test_create_recstr_std("1", "1977-01-09T00:30:00Z"),
        test_create_recstr_std("1", "1977-01-09T01:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T02:30:00Z"),
        test_create_recstr_std("2", "1977-01-09T03:30:00Z"),
        test_create_recstr_std("3", "1977-01-09T04:30:00Z"),
        test_create_recstr_std("4", "1977-01-09T05:30:00Z"),
        test_create_recstr_std("1", "1977-01-09T19:00:00Z"),
        test_create_recstr_std("1", "1977-01-09T20:00:00Z"),
        test_create_recstr_std("3", "1977-01-09T21:00:00Z"),
        test_create_recstr_std("4", "1977-01-09T21:30:00Z"),
        test_create_recstr_std("5", "1977-01-09T22:00:00Z"),
    ]

    rule_str = create_std_rule("count(EventID) >= 3", "2h")

    expected_count = {"_": 11}
    expected_agg_result = [
        agg(3, "_", ["2", "3", "4"], "1977-01-09T03:30:00Z"),
        agg(4, "_", ["1", "3", "4", "5"], "1977-01-09T20:00:00Z"),
    ]
    check_count(rule_str, recs, expected_count, expected_agg_result)
