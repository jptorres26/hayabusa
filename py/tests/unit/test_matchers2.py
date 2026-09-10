"""Port of ``src/detections/rule/matchers/tests.rs`` (lines 1930-3814), part 2 of 2.

See ``test_matchers.py`` for the ``check_select`` helper this file duplicates.
"""

from __future__ import annotations

from helpers_rules import CONFIG_DIR, REPO_ROOT, create_rule, select_record

from hayabusa_py.engine.matchers import MatcherContext
from hayabusa_py.engine.rule import RuleNode
from hayabusa_py.rules.config import load_windash_characters


def matcher_context() -> MatcherContext:
    return MatcherContext(windash_chars=load_windash_characters(CONFIG_DIR), base_dir=REPO_ROOT)


def parse_rule_from_str(rule_str: str) -> RuleNode:
    rule = create_rule(rule_str)
    errors = rule.init(matcher_context())
    assert errors == [], f"rule init failed: {errors}"
    return rule


def check_select(rule_str: str, record_str: str, expect_select: bool) -> None:
    """``check_select`` of matchers/tests.rs (lines 12-53)."""
    rule = parse_rule_from_str(rule_str)
    assert select_record(rule, record_str) == expect_select


# tests.rs:1931-1947
def test_contains_neq_detect():
    # `contains|neq` matches when the field does NOT contain the value.
    rule_str = r"""
        detection:
            selection:
                Channel|contains|neq: cur
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1950-1966
def test_contains_neq_notdetect():
    # `contains|neq` does not match when the field contains the value ("Security" contains "cur").
    rule_str = r"""
        detection:
            selection:
                Channel|contains|neq: cur
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1969-1985
def test_startswith_neq_detect():
    # `startswith|neq` matches when the field does NOT start with the value.
    rule_str = r"""
        detection:
            selection:
                Channel|startswith|neq: Sec
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1988-2004
def test_startswith_neq_notdetect():
    # `startswith|neq` does not match when the field starts with the value.
    rule_str = r"""
        detection:
            selection:
                Channel|startswith|neq: Sec
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2007-2023
def test_endswith_neq_detect():
    # `endswith|neq` matches when the field does NOT end with the value.
    rule_str = r"""
        detection:
            selection:
                Channel|endswith|neq: rity
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2026-2042
def test_endswith_neq_notdetect():
    # `endswith|neq` does not match when the field ends with the value.
    rule_str = r"""
        detection:
            selection:
                Channel|endswith|neq: rity
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2045-2061
def test_fieldref_neq_detect():
    # `fieldref|neq` matches when the two field values are different.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|neq: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "PowerShell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2064-2080
def test_fieldref_neq_notdetect():
    # `fieldref|neq` does not match when the two field values are the same.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|neq: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2083-2099
def test_fieldref_neq_missing_ref_detect():
    # If the referenced field is missing, the values are considered different, so `fieldref|neq` matches.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|neq: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2102-2118
def test_fieldref_contains_neq_detect():
    # `fieldref|contains|neq` matches when the left field does NOT contain the right field's value.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|contains|neq: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "xyz" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2121-2138
def test_fieldref_contains_neq_notdetect():
    # `fieldref|contains|neq` does not match when the left field contains the right field's value
    # ("Security" contains "cur").
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|contains|neq: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "cur" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2141-2157
def test_re_neq_detect():
    # `re|neq` matches when the (case-sensitive) regex does NOT match.
    rule_str = r"""
        detection:
            selection:
                Channel|re|neq: ^Sec.*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2160-2176
def test_re_neq_notdetect():
    # `re|neq` does not match when the regex matches.
    rule_str = r"""
        detection:
            selection:
                Channel|re|neq: ^Sec.*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2179-2196
def test_re_i_neq_notdetect():
    # The `i` (case-insensitive) flag still composes with `neq`: "^sec.*" matches "Security"
    # case-insensitively, so `re|i|neq` does not match.
    rule_str = r"""
        detection:
            selection:
                Channel|re|i|neq: ^sec.*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2199-2217
def test_gt_neq_equal_detect():
    # Numeric `gt|neq`: the value equal to the bound is NOT greater than it, so the base `gt`
    # is false and `neq` matches.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|gt|neq: 1040
            condition: selection
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 1040 }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2220-2237
def test_gt_neq_greater_notdetect():
    # A value greater than the bound satisfies the base `gt`, so `gt|neq` does not match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|gt|neq: 1040
            condition: selection
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 1041 }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2240-2258
def test_gt_neq_missing_field_detect():
    # A missing (or non-numeric) field makes the base `gt` false, so `gt|neq` matches
    # (consistent with the missing-field behavior of the other `neq` forms).
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|gt|neq: 1040
            condition: selection
        """

    record_json_str = r"""
        {
            "Event": {"System": {"Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2261-2277
def test_cidr_neq_detect():
    # `cidr|neq` matches when the IP is NOT in the range (e.g. excluding an internal subnet).
    rule_str = r"""
        detection:
            selection:
                IpAddress|cidr|neq: 192.168.0.0/16
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "10.0.0.1"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2280-2296
def test_cidr_neq_notdetect():
    # `cidr|neq` does not match when the IP is in the range.
    rule_str = r"""
        detection:
            selection:
                IpAddress|cidr|neq: 192.168.0.0/16
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "192.168.1.5"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2299-2316
def test_contains_cased_neq_detect():
    # `contains|cased|neq` is case-sensitive: "security" does not contain "Sec" (different case),
    # so `neq` matches.
    rule_str = r"""
        detection:
            selection:
                Channel|contains|cased|neq: Sec
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2319-2335
def test_contains_cased_neq_notdetect():
    # "Security" contains "Sec" (same case), so `contains|cased|neq` does not match.
    rule_str = r"""
        detection:
            selection:
                Channel|contains|cased|neq: Sec
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2338-2354
def test_eq_field():
    # Verify that equalsfields is correctly detected.
    rule_str = r"""
        detection:
            selection:
                Channel|equalsfield: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2357-2372
def test_eq_field_notdetect():
    # Patterns that equalsfields cannot detect.
    rule_str = r"""
        detection:
            selection:
                Channel|equalsfield: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:2375-2407
def test_eq_field_emptyfield():
    # If a non-existent field is specified, do not detect.
    rule_str = r"""
        detection:
            selection:
                Channel|equalsfield: NoField
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Securiti" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)

    rule_str = r"""
        detection:
            selection:
                NoField|equalsfield: Channel
        details: 'command=%CommandLine%'
        """
    check_select(rule_str, record_json_str, False)

    rule_str = r"""
        detection:
            selection:
                NoField|equalsfield: NoField1
        details: 'command=%CommandLine%'
        """
    check_select(rule_str, record_json_str, False)


# tests.rs:2410-2429
def test_field_null():
    # Verify that a null value matches when the target field does not exist in the record.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    value: Security
                Takoyaki:
                    value: null
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, True)


# tests.rs:2432-2449
def test_field_null_not_detect():
    # Test that a null value requires the target field to be absent: here the field exists,
    # so the rule does not match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: null
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2452-2468
def test_wildcard_converted_starts_with():
    # When a single wildcard is at the end, it is equivalent to starts_with matching.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: A-*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2471-2487
def test_wildcard_converted_starts_with_notdetect():
    # When a single wildcard is at the end, it is equivalent to starts_with matching.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: AA-*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2490-2506
def test_wildcard_converted_starts_with_exact_val():
    # When a single wildcard is at the end and the characters to compare (excluding *) exactly match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: A-HOST*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2509-2526
def test_wildcard_converted_starts_with_shorter_val_notdetect():
    # When a single wildcard is at the end but the event value is shorter than the pattern,
    # it does not match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: A-HOST-*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2529-2545
def test_wildcard_converted_starts_with_multibytes():
    # Patterns containing wildcards and non-ASCII characters use regex matching.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: 社員端末*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "社員端末A"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2548-2564
def test_wildcard_converted_ends_with():
    # When a single wildcard is at the beginning, it is equivalent to ends_with matching.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: '*-HOST'
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2567-2583
def test_wildcard_converted_ends_with_starts_with_exact_val():
    # When a single wildcard is at the beginning and the characters to compare (excluding *) exactly match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: '*A-HOST'
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2586-2603
def test_wildcard_converted_ends_with_shorter_val_notdetect():
    # When a single wildcard is at the beginning, a value that does not end with the
    # pattern's suffix does not match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: '*-HOSTA'
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2606-2623
def test_only_wildcard():
    # A pattern consisting of only a wildcard is converted to ends_with("") and therefore
    # matches any value.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: '*'
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2626-2642
def test_two_wildcards():
    # When two or more wildcards are included, use regex matching.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer: '*-HOST-*'
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "A-HOST-1"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2645-2662
def test_base64_contains():
    # A pattern that matches base64|contains.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Payload|base64|contains:
                    - "http://"
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovLw"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2665-2682
def test_base64offset_contains():
    # A pattern that matches base64offset|contains.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Payload|base64offset|contains:
                    - "http://"
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2690-2705
def test_reordered_cased_contains_is_case_sensitive():
    # |cased|contains == |contains|cased (case-sensitive substring). The old order-sensitive
    # table missed this order and fell back to a case-insensitive regex (ignoring |cased).
    rule_str = r"""
        enabled: true
        detection:
            selection:
                TargetUserName|cased|contains: "Administrators"
        details: 'user %MemberName%'
        """
    match_rec = r"""{"Event": {"System": {"EventID": 4732, "Channel": "Security"}, "EventData": {"TargetUserName": "TestAdministratorsTest"}}}"""
    case_mismatch_rec = r"""{"Event": {"System": {"EventID": 4732, "Channel": "Security"}, "EventData": {"TargetUserName": "testadministratorstest"}}}"""
    check_select(rule_str, match_rec, True)
    # Case-sensitive: a value differing only in case must NOT match.
    check_select(rule_str, case_mismatch_rec, False)


# tests.rs:2708-2724
def test_reordered_contains_base64():
    # |contains|base64 == |base64|contains (pattern is base64-encoded before the substring
    # search). The old order-sensitive table ignored base64 in this order.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Payload|contains|base64:
                    - "http://"
        details: 'x'
        """
    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovLw"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, True)


# tests.rs:2727-2742
def test_reordered_contains_base64offset():
    # |contains|base64offset == |base64offset|contains.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Payload|contains|base64offset:
                    - "http://"
        details: 'x'
        """
    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, True)


# tests.rs:2745-2772
def test_utf16_base64_contains_canonical_and_reordered():
    # |utf16|base64|contains encodes the pattern as UTF-16LE (with a BOM) then base64. This
    # path had no unit coverage before; verify both the canonical order and the reordered
    # |base64|utf16|contains (which the old index-based table did not recognize).
    canonical = r"""
        enabled: true
        detection:
            selection:
                Payload|utf16|base64|contains:
                    - "http://"
        details: 'x'
        """
    reordered = r"""
        enabled: true
        detection:
            selection:
                Payload|base64|utf16|contains:
                    - "http://"
        details: 'x'
        """
    # Payload holds base64(BOM + UTF-16LE("http://")).
    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "//5oAHQAdABwADoALwAvAA"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(canonical, record_json_str, True)
    check_select(reordered, record_json_str, True)


# tests.rs:2775-2792
def test_base64offset_contains_not_match():
    # A pattern that does not match base64offset|contains.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Payload|base64offset|contains:
                    - "test"
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Tester"}, "EventData":{"Payload": "aHR0cDovL"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2795-2811
def test_cidr_ipv4_detect():
    # IPs matching CIDR.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 192.168.0.0/16
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "192.168.0.1"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2814-2830
def test_cidr_ipv4_not_detect():
    # IPs not matching CIDR.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2600:1f18:130c:d900::/56
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "8.8.8.8"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2833-2849
def test_cidr_ipv6_detect():
    # IPs matching CIDR.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2001:db8:1234::/48
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "2001:db8:1234:ffff:ffff:ffff:ffff:ffff"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2852-2868
def test_cidr_ipv6_not_detect():
    # IPs not matching CIDR.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 2001:db8:1234::/48
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4624}, "EventData": {"IpAddress": "2001:db8:1111:ffff:ffff:ffff:ffff:ffff"} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2871-2887
def test_cidr_ip_field_not_exists_not_detect():
    # When the IP address field does not exist in the record, the rule does not match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                IpAddress|cidr: 192.168.0.0/16
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4624} },
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:2890-2914
def test_detect_backslash_exact_match():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory: 'C:\Windows\'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2917-2940
def test_detect_startswith_backslash1():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|startswith: C:\Windows\
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2943-2966
def test_detect_startswith_backslash2():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|startswith: C:\Windows\
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows_\\hoge.exe"
            }
          }
        }"""

    check_select(
        rule_str, record_json_str, False
    )  # Expect false: the backslash must match literally.


# tests.rs:2969-2992
def test_detect_contains_backslash1():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|contains: \Windows\
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:2995-3018
def test_detect_contains_backslash2():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 1040
                Data|contains: \Windows\
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1040,
              "Channel": "Application"
            },
            "EventData": {
              "Data": "C:\\Windows_\\hoge.exe"
            }
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:3021-3045
def test_detect_backslash_endswith():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory|endswith: 'C:\Windows\system32\'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3048-3072
def test_detect_backslash_regex():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: 'Microsoft-Windows-Sysmon/Operational'
                EventID: 1
                CurrentDirectory|re: '.*system32\\'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3075-3103
def test_all_only_detect_case():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'indows\'
            selection2:
                - 1
                - 2
            condition: selection1 and selection2
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3106-3134
def test_all_only_no_detect_case():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'false'
            selection2:
                - 1
                - 2
            condition: selection1 and selection2
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:3137-3164
def test_all_only_detected_and_selection_false():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'indows\'
            selection2:
                - 'dummy'
            condition: selection1 and selection2
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:3167-3195
def test_all_only_not_detect_and_selection_false():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                '|all':
                    - 'Sysmon/Operational'
                    - 'false'
            selection2:
                - 3
                - 2
            condition: selection1 and selection2
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:3198-3234
def test_contains_windash():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '-addstore'
            condition: selection1
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /addstore"
            }
          }
        }"""

    record_json_str2 = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test -addstore"
            }
          }
        }"""
    check_select(rule_str, record_json_str, True)
    check_select(rule_str, record_json_str2, True)


# tests.rs:3237-3275
def test_contains_all_windash():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '-addstore'
                    - '-test-test'
            condition: selection1
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test -test-test /addstore"
            }
          }
        }"""

    record_json_str2 = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test -addstore"
            }
          }
        }"""
    check_select(rule_str, record_json_str, True)
    check_select(rule_str, record_json_str2, False)


# tests.rs:3278-3365
def test_contains_windash_multitype_dash():
    rule_str_en_dash = r"""
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '–addstore'
            condition: selection1
        """
    rule_str_em_dash = r"""
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '—addstore'
            condition: selection1
        """
    rule_str_horizontal_bar = r"""
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|windash': '―addstore'
            condition: selection1
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /addstore"
            }
          }
        }"""

    record_json_str_en = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test –addstore"
            }
          }
        }"""

    record_json_str_em = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test —addstore"
            }
          }
        }"""

    record_json_str_horizontal = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test ―addstore"
            }
          }
        }"""

    check_select(rule_str_en_dash, record_json_str, True)
    check_select(rule_str_en_dash, record_json_str_en, True)
    check_select(rule_str_en_dash, record_json_str_em, True)
    check_select(rule_str_en_dash, record_json_str_horizontal, True)
    check_select(rule_str_em_dash, record_json_str, True)
    check_select(rule_str_em_dash, record_json_str_en, True)
    check_select(rule_str_em_dash, record_json_str_em, True)
    check_select(rule_str_em_dash, record_json_str_horizontal, True)
    check_select(rule_str_horizontal_bar, record_json_str, True)
    check_select(rule_str_horizontal_bar, record_json_str_en, True)
    check_select(rule_str_horizontal_bar, record_json_str_em, True)
    check_select(rule_str_horizontal_bar, record_json_str_horizontal, True)


# tests.rs:3368-3491
def test_contains_all_windash_multitype_dash():
    rule_str_en_dash = r"""
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '–addstore'
                    - '–test–test'
            condition: selection1
        """

    rule_str_em_dash = r"""
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '—addstore'
                    - '—test—test'
            condition: selection1
        """

    rule_str_horizontal_bar = r"""
        enabled: true
        detection:
            selection1:
                'CommandLine|contains|all|windash':
                    - '―addstore'
                    - '―test―test'
            condition: selection1
        """

    record_json_str_en_dash = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test –test–test /addstore"
            }
          }
        }"""

    record_json_str_en_dash2 = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test –addstore"
            }
          }
        }"""

    record_json_str_em_dash = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test —test—test /addstore"
            }
          }
        }"""

    record_json_str_em_dash2 = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test —addstore"
            }
          }
        }"""

    record_json_str_horizontal_bar = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test ―test―test /addstore"
            }
          }
        }"""

    record_json_str_horizontal_bar2 = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CommandLine": "test /test/test ―addstore"
            }
          }
        }"""

    check_select(rule_str_en_dash, record_json_str_en_dash, True)
    check_select(rule_str_en_dash, record_json_str_en_dash2, False)
    check_select(rule_str_em_dash, record_json_str_em_dash, True)
    check_select(rule_str_em_dash, record_json_str_em_dash2, False)
    check_select(
        rule_str_horizontal_bar,
        record_json_str_horizontal_bar,
        True,
    )
    check_select(
        rule_str_horizontal_bar,
        record_json_str_horizontal_bar2,
        False,
    )


# tests.rs:3494-3516
def test_exists_true():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel|exists: true
            condition: selection1
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""
    check_select(rule_str, record_json_str, True)


# tests.rs:3519-3534
def test_re_caseinsensitive_detect():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer|re|i: ABC
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "abc"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3537-3559
def test_exists_null_true():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Channel|exists: true
            condition: selection1
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": ""
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""
    check_select(rule_str, record_json_str, True)


# tests.rs:3562-3577
def test_re_multiline_detect():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer|re|m: ^ABC$
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "ABC\nDEF"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3580-3602
def test_exists_false():
    rule_str = r"""
        enabled: true
        detection:
            selection1:
                Dummy|exists: false
            condition: selection1
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1,
              "Channel": ""
            },
            "EventData": {
              "CurrentDirectory": "C:\\Windows\\system32\\"
            }
          }
        }"""
    check_select(rule_str, record_json_str, True)


# tests.rs:3605-3620
def test_re_singleline_detect():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer|re|s: A.*F
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""{
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "ABC\nDEF"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3623-3645
def test_ge():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|gt: 1040
            condition: selection
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3648-3670
def test_ge_not():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|gt: 1040
            condition: selection
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1040
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:3673-3695
def test_lt():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3697-3718
def test_lt_not():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1040
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:3721-3743
def test_gte():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|gte: 1040
            condition: selection
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3745-3766
def test_gte_not():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|gte: 1040
            condition: selection
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:3769-3791
def test_lte():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|lte: 1040
            condition: selection
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1039
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:3793-3814
def test_lte_not():
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID|lt: 1040
            condition: selection
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 1041
            },
            "EventData": {
              "Data": "C:\\Windows\\hoge.exe"
            }
          }
        }"""
    check_select(rule_str, record_json_str, False)
