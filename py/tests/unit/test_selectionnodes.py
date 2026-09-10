"""Port of the ``mod tests`` of ``src/detections/rule/selectionnodes.rs`` (lines 420-796)."""

from __future__ import annotations

from helpers_rules import check_select


# selectionnodes.rs:478-497
def test_detect_multiple_regex_and():
    # Verify that AND conditions are correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4103
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# selectionnodes.rs:499-519
def test_notdetect_multiple_regex_and():
    # Verify that if even one condition in an AND condition does not match, it is not detected.
    # In this example, the Computer value is different.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4103
                Computer: DESKTOP-ICHIICHIN
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# selectionnodes.rs:521-541
def test_detect_or():
    # Verify that OR conditions are correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    - PowerShell
                    - Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# selectionnodes.rs:543-563
def test_detect_or2():
    # Verify that OR conditions are correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    - PowerShell
                    - Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "PowerShell", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# selectionnodes.rs:565-585
def test_notdetect_or():
    # Verify that an OR condition does not match when none of the listed values match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    - PowerShell
                    - Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "not detect", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# selectionnodes.rs:587-607
def test_neq_contains_all_detect():
    # `contains|all|neq` with a list negates the AND-linked comparison (De Morgan):
    # NOT(contains "cur" AND contains "ity"). "curabc" contains "cur" but not "ity",
    # so NOT(true AND false) = true -> MATCH.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|contains|all|neq:
                    - cur
                    - ity
        details: 'command=%CommandLine%'
        """
    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "curabc"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, True)


# selectionnodes.rs:609-627
def test_neq_contains_all_notdetect():
    # NOT(contains "cur" AND contains "ity"). "curity" contains both, so NOT(true AND true) = false.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|contains|all|neq:
                    - cur
                    - ity
        details: 'command=%CommandLine%'
        """
    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "curity"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# selectionnodes.rs:629-647
def test_neq_data_array_notdetect():
    # Multi-valued EventData.Data with neq: Data = ["X","Y"], `neq: X`.
    # The negation applies over the whole field: NOT(any element == X). X is present, so NO MATCH.
    # (This must agree with condition-level `not` on the same data.)
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Data|neq: X
        details: 'command=%CommandLine%'
        """
    record_json_str = r"""
        {
            "Event": {"EventData": {"Data": ["X", "Y"]}, "System": {"EventID": 4103, "Channel": "Sec"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# selectionnodes.rs:649-665
def test_neq_data_array_detect():
    # Data = ["X","Y"], `neq: Z`. Z is absent, so NOT(any element == Z) = NOT(false) = MATCH.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Data|neq: Z
        details: 'command=%CommandLine%'
        """
    record_json_str = r"""
        {
            "Event": {"EventData": {"Data": ["X", "Y"]}, "System": {"EventID": 4103, "Channel": "Sec"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, True)


# selectionnodes.rs:667-685
def test_neq_repeated_is_idempotent():
    # Repeating `neq` is idempotent (matches Sigma's SigmaNegateModifier, which sets `negated = true`
    # rather than toggling). `Channel|neq|neq: Security` against Channel=Security stays a single
    # negation: NOT(Channel == Security) = false.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|neq|neq: Security
        details: 'command=%CommandLine%'
        """
    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# selectionnodes.rs:687-708
def test_neq_list_detect():
    # A list of values under `neq` means "different from ALL of them" (De Morgan).
    # "PowerShell" differs from both "Security" and "System", so it matches.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|neq:
                    - Security
                    - System
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "PowerShell"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# selectionnodes.rs:710-731
def test_neq_list_notdetect_first():
    # If the field equals any value in the `neq` list, it must not match.
    # (If the list were treated as OR instead of AND, this would wrongly match.)
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|neq:
                    - Security
                    - System
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# selectionnodes.rs:733-753
def test_neq_list_notdetect_second():
    # Same as above but matching the second value in the list.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|neq:
                    - Security
                    - System
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "System"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# selectionnodes.rs:755-774
def test_detect_event_id_wildcard():
    # Verify that EventID wildcard matching is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 41*3
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# selectionnodes.rs:776-795
def test_detect_event_id_question():
    # Verify that EventID single-character "?" matching is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 41?3
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)
