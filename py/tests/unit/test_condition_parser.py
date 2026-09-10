"""Port of the ``mod tests`` of ``src/detections/rule/condition_parser.rs`` (lines 445-1603)."""

from __future__ import annotations

from helpers_rules import check_rule_parse_error, check_select, init_rule

from hayabusa_py.engine.condition import convert_condition

# condition_parser.rs:456-472 — minimal event record shared by most of the tests in this module.
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


# condition_parser.rs:527-558
def test_no_condition():
    # Verify that parsing succeeds when there is only one selection even without a condition expression.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7040
                param1: 'Windows Event Log'
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    record_json_str = r"""
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

    check_select(rule_str, record_json_str, True)


# condition_parser.rs:560-592
def test_no_condition_notdetect():
    # Verify that parsing succeeds when there is only one selection even without a condition expression.
    # This is a non-detection pattern.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7041
                param1: 'Windows Event Log'
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    record_json_str = r"""
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

    check_select(rule_str, record_json_str, False)


# condition_parser.rs:594-611
def test_condition_and_detect():
    # Test for patterns using and in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:613-631
def test_condition_and_notdetect():
    # Test for patterns using and in condition.
    # This is a non-hit pattern.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:633-651
def test_condition_and_notdetect2():
    # Test for patterns using and in condition.
    # This is a non-hit pattern.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:653-671
def test_condition_and_detect3():
    # Test for patterns using and in condition.
    # This is a non-hit pattern.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:673-691
def test_condition_and_notdetect4():
    # Test for patterns using and in condition.
    # This is a non-hit pattern.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:693-711
def test_condition_and_notdetect5():
    # Test for patterns using and in condition.
    # This is a non-hit pattern.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 and selection2 and selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:713-730
def test_condition_or_detect():
    # Test for patterns using or in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:732-749
def test_condition_or_detect2():
    # Test for patterns using or in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:751-768
def test_condition_or_detect3():
    # Test for patterns using or in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:770-787
def test_condition_or_detect4():
    # Test for patterns using or in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:789-806
def test_condition_or_detect5():
    # Test for patterns using or in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:808-825
def test_condition_or_detect6():
    # Test for patterns using or in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:827-844
def test_condition_or_detect7():
    # Test for patterns using or in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:846-863
def test_condition_or_notdetect():
    # Test for patterns using or in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            selection2:
                EventID: 7041
            selection3:
                param1: 'Windows Event Logn'
            condition: selection1 or selection2 or selection3
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:865-878
def test_condition_not_detect():
    # Test for patterns using not in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'Systemn'
            condition: not selection1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:880-893
def test_condition_not_notdetect():
    # Test for patterns using not in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            condition: not selection1
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:895-912
def test_condition_parenthesis_detect():
    # Test using parentheses in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection2 and (selection2 or selection3)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:914-931
def test_condition_parenthesis_not_detect():
    # Test using parentheses in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection2 and (selection2 and selection3)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:933-950
def test_condition_many_parenthesis_detect():
    # Test using many parentheses in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection2 and (((selection2 or selection3)))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:952-969
def test_condition_manyparenthesis_not_detect():
    # Test using many parentheses in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: selection2 and ((((selection2 and selection3))))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:971-988
def test_condition_notparenthesis_detect():
    # Test combining parentheses and not in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: (selection2 and selection1) and not ((selection2 and selection3))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:990-1007
def test_condition_notparenthesis_notdetect():
    # Test combining parentheses and not in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: (selection2 and selection1) and not (not(selection2 and selection3))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:1009-1026
def test_condition_manyparenthesis_detect2():
    # Cases using various parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: (selection2 and selection1) and (selection2 or selection3)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:1028-1045
def test_condition_manyparenthesis_notdetect2():
    # Cases using various parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            condition: (selection2 and selection1) and (selection2 and selection3)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:1047-1066
def test_condition_manyparenthesis_detect3():
    # Cases using various parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            selection4:
                param2: 'auto start'
            condition: (selection1 and (selection2 and ( selection3 and selection4 )))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:1068-1087
def test_condition_manyparenthesis_notdetect3():
    # Cases using various parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            selection4:
                param2: 'auto start'
            condition: (selection1 and (selection2 and ( selection3 and selection4 )))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:1089-1108
def test_condition_manyparenthesis_detect4():
    # Cases using various parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            selection4:
                param2: 'auto start'
            condition: (selection1 and (selection2 and ( selection3 or selection4 )))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:1110-1129
def test_condition_manyparenthesis_notdetect4():
    # Cases using various parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Logn'
            selection4:
                param2: 'auto startn'
            condition: (selection1 and (selection2 and ( selection3 or selection4 )))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:1131-1154
def test_rule_parseerror_no_condition():
    # Having multiple selections without a condition is an error.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    _rule, errors = init_rule(rule_str)

    assert errors == ["There is no condition node under detection."]


# condition_parser.rs:1156-1179
def test_condition_err_condition_forbid_character():
    # The condition contains a character that cannot be tokenized (the hyphen in
    # "selection-1").
    rule_str = r"""
        enabled: true
        detection:
            selection-1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection-1 and selection2
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. An unusable character was found."],
    )


# condition_parser.rs:1181-1202
def test_condition_err_leftparenthesis_over():
    # Too many left parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and ((selection2)
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. ')' was expected but not found."],
    )


# condition_parser.rs:1204-1225
def test_condition_err_rightparenthesis_over():
    # Too many right parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and (selection2))
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. '(' was expected but not found."],
    )


# condition_parser.rs:1227-1248
def test_condition_err_parenthesis_direction_wrong():
    # Wrong direction of parentheses.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 and )selection2(
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. ')' was expected but not found."],
    )


# condition_parser.rs:1250-1266
def test_condition_err_no_logical():
    # Using two selection names not connected by AND or OR is an error.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 selection2
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        [
            "A condition parse error has occurred. Unknown error. Maybe it is because there are multiple names of selection nodes."
        ],
    )


# condition_parser.rs:1268-1290
def test_condition_err_first_logical():
    # A logical operator at the beginning of the condition is an error.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: and selection1 or selection2
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. An illegal logical operator(and, or) was found."],
    )


# condition_parser.rs:1292-1314
def test_condition_err_last_logical():
    # A logical operator at the end of the condition is an error.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 or selection2 or
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. An illegal logical operator(and, or) was found."],
    )


# condition_parser.rs:1316-1332
def test_condition_err_consecutive_logical():
    # Consecutive logical operators are an error.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 or or selection2
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. The use of a logical operator(and, or) was wrong."],
    )


# condition_parser.rs:1334-1353
def test_condition_err_only_not():
    # A not without an operand is an error.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 or ( not )
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. An illegal not was found."],
    )


# condition_parser.rs:1355-1374
def test_condition_err_not_not():
    # Consecutive nots are not allowed.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
                EventID: 7041
            selection2:
                param1: 'Windows Event Log'
            condition: selection1 or ( not not )
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_rule_parse_error(
        rule_str,
        ["A condition parse error has occurred. Not is continuous."],
    )


# condition_parser.rs:1376-1393
def test_convert_condition_all_of_selection():
    condition = "all of selection*"

    keys = ["selection1", "selection2"]
    result = convert_condition(condition, keys)
    expected = "(selection1 and selection2)"
    assert result == expected

    keys = ["selection1", "selection2", "selection3"]
    result = convert_condition(condition, keys)
    expected = "(selection1 and selection2 and selection3)"
    assert result == expected


# condition_parser.rs:1395-1408
def test_convert_condition_multiple_all_of_selection():
    condition = "all of selection* and all of filter*"

    keys = ["selection1", "selection2", "filter1", "filter2"]
    result = convert_condition(condition, keys)
    expected = "(selection1 and selection2) and (filter1 and filter2)"
    assert result == expected


# condition_parser.rs:1410-1427
def test_convert_condition_one_of_selection():
    condition = "1 of selection*"

    keys = ["selection1", "selection2"]
    result = convert_condition(condition, keys)
    expected = "(selection1 or selection2)"
    assert result == expected

    keys = ["selection1", "selection2", "selection3"]
    result = convert_condition(condition, keys)
    expected = "(selection1 or selection2 or selection3)"
    assert result == expected


# condition_parser.rs:1429-1441
def test_convert_condition_multiple_one_of_selection():
    condition = "1 of selection* and 1 of filter*"
    keys = ["selection1", "selection2", "filter1", "filter2"]
    result = convert_condition(condition, keys)
    expected = "(selection1 or selection2) and (filter1 or filter2)"
    assert result == expected


# condition_parser.rs:1443-1457
def test_convert_condition_convert_complex_condition():
    condition = "all of selection* and test1 or test2 or 1 of filter*"
    keys = ["selection1", "selection2", "test", "filter1", "filter2"]
    result = convert_condition(condition, keys)
    expected = "(selection1 and selection2) and test1 or test2 or (filter1 or filter2)"
    assert result == expected


# condition_parser.rs:1459-1465
def test_convert_condition_not_convert():
    condition = "selection1 and selection2"
    keys = ["selection1", "selection2"]
    result = convert_condition(condition, keys)
    assert result == condition


# condition_parser.rs:1467-1484
def test_condition_1_of_select_detect():
    # Test for patterns using "1 of selection*" in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: 1 of selection*
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:1486-1503
def test_condition_1_of_select_not_detect():
    # Test for patterns using "1 of selection*" in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'NODETECT'
            selection2:
                EventID: 9999
            selection3:
                param1: 'NODETECT'
            condition: 1 of selection*
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:1505-1522
def test_condition_all_of_select_detect():
    # Test for patterns using "all of selection*" in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'System'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: all of selection*
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, True)


# condition_parser.rs:1524-1541
def test_condition_all_of_select_not_detect():
    # Test for patterns using "all of selection*" in condition.
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel: 'NOTDETECT'
            selection2:
                EventID: 7040
            selection3:
                param1: 'Windows Event Log'
            condition: all of selection*
        details: 'Service name : %param1%¥nMessage : Event Log Service Stopped¥nResults: Selective event log manipulation may follow this event.'
        """

    check_select(rule_str, SIMPLE_RECORD_STR, False)


# condition_parser.rs:1543-1602
def test_condition_complex_of_selection():
    def rule_str(condition: str) -> str:
        # Rust: format!(r#"..."#) with a single `{condition}` placeholder.
        return r"""
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7045
            suspicious1:
                ImagePath|contains:
                    - 'A'
                    - 'B'
            suspicious2a:
                ImagePath|contains: 'C'
            suspicious2b:
                ImagePath|contains:
                    - 'D'
                    - 'E'
            filter_thor_remote:
                ImagePath|startswith: 'F'
            filter_defender_def_updates:
                ImagePath|startswith: 'G'
            condition:
                {condition}
        """.replace("{condition}", condition)

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 7045,
              "Channel": "System"
            },
            "EventData": {
              "ImagePath": "A B C D E F G"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    case0 = "selection and all of suspicious2* and not 1 of filter_*"
    case1 = "selection and ( suspicious1 or all of suspicious2* ) and not 1 of filter_*"
    case2 = "selection and ( suspicious1 or all of suspicious2* ) and 1 of filter_*"
    case3 = "selection and not ( suspicious1 or all of suspicious2* ) and not 1 of filter_*"
    case4 = "selection and not ( suspicious1 or all of suspicious2* ) and 1 of filter_*"
    case5 = "selection and ( suspicious1 and not all of suspicious2* ) and 1 of filter_*"

    check_select(rule_str(case0), record_json_str, True)
    check_select(rule_str(case1), record_json_str, True)
    check_select(rule_str(case2), record_json_str, False)
    check_select(rule_str(case3), record_json_str, False)
    check_select(rule_str(case4), record_json_str, False)
    check_select(rule_str(case5), record_json_str, False)
