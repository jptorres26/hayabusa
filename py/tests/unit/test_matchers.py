"""Port of ``src/detections/rule/matchers/tests.rs`` (lines 1-1928), part 1 of 2.

The Rust ``check_select`` builds a full ``StoredStatic`` (with ``rules/config/windash_characters.txt``
loaded and relative ``regexes:``/``allowlist:`` paths resolved from the repository root); here the
equivalent is a ``MatcherContext`` with the windash fixture and ``base_dir=REPO_ROOT``.
"""

from __future__ import annotations

from helpers_rules import CONFIG_DIR, REPO_ROOT, create_rule, select_record

from hayabusa_py.engine.matchers import (
    AllowlistFileMatcher,
    DefaultMatcher,
    FastKind,
    FastMatch,
    MatcherContext,
    MinlengthMatcher,
    RegexesFileMatcher,
    wildcard_to_regex,
)
from hayabusa_py.engine.rule import RuleNode
from hayabusa_py.engine.selection import LeafSelectionNode, NarySelectionNode
from hayabusa_py.rules.config import load_windash_characters


def matcher_context() -> MatcherContext:
    """The matcher-relevant part of the ``StoredStatic`` built by the Rust ``check_select``."""
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


# tests.rs:56-260
def test_rule_parse():
    # Load the rule file in YAML format.
    rule_str = r"""
        title: PowerShell Execution Pipeline
        description: hogehoge
        enabled: true
        author: Yea
        logsource:
            product: windows
        detection:
            selection:
                Channel: Microsoft-Windows-PowerShell/Operational
                EventID: 4103
                ContextInfo:
                    - Host Application
                    - ホスト アプリケーション
                ImagePath:
                    min_length: 1234321
                    regexes: test_files/config/regex/detectlist_suspicous_services.txt
                    allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        falsepositives:
            - unknown
        level: medium
        details: 'command=%CommandLine%'
        creation_date: 2020/11/8
        updated_date: 2020/11/8
        """
    rule_node = parse_rule_from_str(rule_str)
    selection_node = rule_node.detection.name_to_selection["selection"]

    # Root
    detection_children = selection_node.get_children()
    assert len(detection_children) == 4

    # Channel
    # Verify that LeafSelectionNode is correctly loaded.
    child_node = detection_children[0]
    assert isinstance(child_node, LeafSelectionNode)
    assert child_node.get_key() == "Channel"
    assert len(child_node.get_children()) == 0

    # Verify that the comparison matcher is correct.
    matcher = child_node.matcher
    assert matcher is not None
    assert isinstance(matcher, DefaultMatcher)

    assert matcher.fast_match is not None
    assert matcher.fast_match == [
        FastMatch(FastKind.EXACT, "Microsoft-Windows-PowerShell/Operational")
    ]

    # EventID
    # Verify that LeafSelectionNode is correctly loaded.
    child_node = detection_children[1]
    assert isinstance(child_node, LeafSelectionNode)
    assert child_node.get_key() == "EventID"
    assert len(child_node.get_children()) == 0

    # Verify that the comparison matcher is correct.
    matcher = child_node.matcher
    assert matcher is not None
    assert isinstance(matcher, DefaultMatcher)
    assert matcher.fast_match is not None

    # ContextInfo
    # Verify that an OR-op NarySelectionNode is correctly loaded.
    child_node = detection_children[2]
    assert isinstance(child_node, NarySelectionNode)
    assert child_node.all_of is False  # LogicalOp::Any
    ancestors = child_node.get_children()
    assert len(ancestors) == 2

    # Test patterns where LeafSelectionNode is under the OR node.
    # Verify that the Host Application node, which is a LeafSelectionNode, is correct.
    hostapp_en_node = ancestors[0]
    assert isinstance(hostapp_en_node, LeafSelectionNode)

    hostapp_en_matcher = hostapp_en_node.matcher
    assert hostapp_en_matcher is not None
    assert isinstance(hostapp_en_matcher, DefaultMatcher)
    assert hostapp_en_matcher.fast_match is not None
    assert hostapp_en_matcher.fast_match == [FastMatch(FastKind.EXACT, "Host Application")]

    # Verify that the Japanese-locale host application node, which is a LeafSelectionNode,
    # is correct.
    hostapp_jp_node = ancestors[1]
    assert isinstance(hostapp_jp_node, LeafSelectionNode)

    hostapp_jp_matcher = hostapp_jp_node.matcher
    assert hostapp_jp_matcher is not None
    assert isinstance(hostapp_jp_matcher, DefaultMatcher)
    assert hostapp_jp_matcher.fast_match is not None
    assert hostapp_jp_matcher.fast_match == [FastMatch(FastKind.EXACT, "ホスト アプリケーション")]

    # ImagePath
    # Verify that an AND-op NarySelectionNode is correctly loaded.
    child_node = detection_children[3]
    assert isinstance(child_node, NarySelectionNode)
    assert child_node.all_of is True  # LogicalOp::All
    ancestors = child_node.get_children()
    assert len(ancestors) == 3

    # Verify that min-len is correctly loaded.
    ancestor_node = ancestors[0]
    assert isinstance(ancestor_node, LeafSelectionNode)
    ancestor_matcher = ancestor_node.matcher
    assert ancestor_matcher is not None
    assert isinstance(ancestor_matcher, MinlengthMatcher)
    assert ancestor_matcher.min_len == 1234321

    # Verify that regexes are correctly loaded.
    ancestor_node = ancestors[1]
    assert isinstance(ancestor_node, LeafSelectionNode)
    ancestor_matcher = ancestor_node.matcher
    assert ancestor_matcher is not None
    assert isinstance(ancestor_matcher, RegexesFileMatcher)

    # Verify that the contents match the regexes file.
    # (Rust compares ``Regex::as_str()``; ``compile_regex`` leaves these particular patterns
    # untouched - no leading inline flags and no ``^(?:...)$`` wrapper - so ``.pattern`` is the
    # file line verbatim.)
    csvcontent = ancestor_matcher.regexes

    assert len(csvcontent) == 16
    assert csvcontent[0].pattern == r"^cmd.exe /c echo [a-z]{6} > \\\\.\\pipe\\[a-z]{6}$"
    assert csvcontent[13].pattern == r"\\cvtres\.exe.*\\AppData\\Local\\Temp\\[A-Z0-9]{7}\.tmp"

    # Verify that the allowlist file can be loaded.
    ancestor_node = ancestors[2]
    assert isinstance(ancestor_node, LeafSelectionNode)
    ancestor_matcher = ancestor_node.matcher
    assert ancestor_matcher is not None
    assert isinstance(ancestor_matcher, AllowlistFileMatcher)

    csvcontent = ancestor_matcher.regexes
    assert len(csvcontent) == 2

    assert (
        csvcontent[0].pattern == r'^"C:\\Program Files\\Google\\Chrome\\Application\\chrome\.exe"'
    )
    assert csvcontent[1].pattern == r'^"C:\\Program Files\\Google\\Update\\GoogleUpdate\.exe"'


# tests.rs:263-280
def test_notdetect_regex_eventid():
    # Since it is an exact match, verify that prefix matching does not detect.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 410}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:283-300
def test_notdetect_regex_eventid2():
    # Since it is an exact match, verify that suffix matching does not detect.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:303-320
def test_detect_regex_eventid():
    # This should be detected for EventID=4103.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4103
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:323-341
def test_notdetect_regex_str():
    # Also verify with string-like data.
    # Since it is an exact match, verify that it does not match as a prefix.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Securit"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:344-362
def test_notdetect_regex_str2():
    # Also verify with string-like data.
    # Since it is an exact match, verify that it does not match as a suffix.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ecurity"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:365-382
def test_detect_regex_str():
    # Verify that exact matching also works with string-like data.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:385-402
def test_notdetect_regex_emptystr():
    # Verify that an empty string value does not match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"Channel": ""}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:405-423
def test_notdetect_minlen():
    # Verify that min_length does not match when the value is shorter.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security9", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:426-444
def test_detect_minlen():
    # Verify that minlen is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:447-465
def test_detect_minlen2():
    # Verify that minlen is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security.11", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:468-486
def test_detect_minlen_and():
    # Verify that minlen is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 10
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:489-507
def test_notdetect_minlen_and():
    # Verify that min_length does not match when the value is shorter.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    min_length: 11
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security10", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:510-527
def test_detect_regex():
    # Verify that regex can be used.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|re: ^Program$
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:530-547
def test_detect_regex_partial_match():
    # Partial regex match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Computer|re: DESKTOP
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Program", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:550-573
def test_detect_regexes():
    # Verify that the allowlist file is correctly handled (despite the test name, the rule
    # only uses an allowlist).
    # In this case, the EventID matches, but since it matches the allowlist, it should not be
    # detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        """

    # Note that when using double quotes as values in JSON, \ escape is required.
    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:576-597
def test_detect_allowlist():
    # Verify that the allowlist is correctly handled.
    # In this case, the EventID matches, but since it matches the allowlist, it should not be detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        """

    # Note that when using double quotes as values in JSON, \ escape is required.
    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Update\\GoogleUpdate.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:600-619
def test_detect_allowlist2():
    # Verify that the allowlist is correctly handled.
    # In this case, the EventID matches, but since it matches the allowlist, it should not be detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4103
                Channel:
                    - allowlist: test_files/config/regex/allowlist_legitimate_services.txt
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:622-651
def test_detect_startswith1():
    # Verify that startswith is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:654-683
def test_detect_startswith2():
    # Verify that startswith is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:686-714
def test_detect_startswith_case_insensitive():
    # Verify that startswith is case-insensitive.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith: "ADMINISTRATORS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:717-746
def test_detect_startswith_cased():
    # Verify that startswith|cased is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:749-778
def test_detect_startswith_cased2():
    # Verify that startswith|cased is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|startswith|cased: "administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:781-810
def test_detect_endswith1():
    # Verify that endswith is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:813-841
def test_detect_endswith2():
    # Verify that endswith is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:844-872
def test_detect_endswith_case_insensitive():
    # Test to verify that endswith detects without distinguishing case.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith: "ADministRATORS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:875-903
def test_detect_endswith_cased1():
    # Verify that endswith|cased is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:906-934
def test_detect_endswith_cased2():
    # Verify that endswith|cased is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "test"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:937-965
def test_detect_endswith_cased3():
    # Verify that endswith|cased is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|endswith|cased: "sTest"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "AdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    check_select(rule_str, record_json_str, True)


# tests.rs:968-997
def test_detect_contains1():
    # Verify that contains is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1000-1029
def test_detect_contains2():
    # Verify that contains is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "Testministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1032-1060
def test_detect_contains_case_insensitive():
    # Test to verify that contains detects without distinguishing case.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains: "ADminIstraTOrS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "Testministrators"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:1063-1092
def test_detect_contains_cased1():
    # Verify that contains|cased is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains|cased: "Administrators"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestAdministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1095-1124
def test_detect_contains_cased2():
    # Verify that contains|cased is correctly detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
                EventID: 4732
                TargetUserName|contains|cased: "MinistratorS"
        details: 'user added to local Administrators UserName: %MemberName% SID: %MemberSid%'
        """

    record_json_str = r"""
        {
          "Event": {
            "System": {
              "EventID": 4732,
              "Channel": "Security"
            },
            "EventData": {
              "TargetUserName": "TestministratorsTest"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1127-1144
def test_detect_wildcard_multibyte():
    # Verification with multi-byte characters.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: ホストアプリケーション
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1147-1163
def test_detect_wildcard_multibyte_notdetect():
    # Verification with multi-byte characters.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: ホスとアプリケーション
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:1166-1183
def test_wildcard_case_insensitive():
    # Wildcards match regardless of case.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1186-1203
def test_wildcard_question_fullmatch():
    # A "?" wildcard matches exactly one character of the full value.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Sec?rity
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Sec1rity"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1206-1224
def test_wildcard_question_no_substring_match():
    # Patterns that fall back to regex matching (here because of "?") must match the whole
    # value, not a substring of it (regression test for #1815).
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: Sec?rity
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "MySec1rityLog"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1227-1244
def test_wildcard_midstring_asterisk_fullmatch():
    # A mid-string "*" wildcard (not convertible to a fast match) matches the full value.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: net*user
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "netXYZuser"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1247-1265
def test_wildcard_midstring_asterisk_no_substring_match():
    # A mid-string "*" wildcard must not match a value with extra leading/trailing
    # characters (regression test for #1815).
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: net*user
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "mynetXuserZ"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1268-1286
def test_wildcard_multibyte_asterisk_fullmatch():
    # Non-ASCII patterns with "*" always take the regex path; the prefix part must still
    # be anchored to the start of the value.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: ホスト*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "ホストアプリケーション"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1289-1307
def test_wildcard_multibyte_asterisk_no_substring_match():
    # A non-ASCII prefix pattern must not match a value that merely contains the prefix
    # (regression test for #1815).
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: ホスト*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Myホストログ"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1310-1328
def test_grep_substring_match_still_works():
    # Keyword (grep) searches with no field name intentionally keep substring semantics:
    # anchoring added for field matches (#1815) must not apply here.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                - ecurit
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1331-1353
def test_all_keyword_wildcard_substring_match():
    # A keyless `|all` selection is matched against the whole-record string with substring
    # (contains) semantics, even when a value falls back to regex matching (here because of
    # the `?` wildcard). The anchoring added for field matches (#1815) must not apply to the
    # `|all` whole-record search, otherwise it would require the entire record to equal the
    # pattern and never match. `Windo?s` matches the "Windows" contained in the Channel value.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                '|all':
                    - 'Windo?s'
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Microsoft-Windows-Sysmon/Operational"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1356-1375
def test_startswith_multibyte_fallback_fullmatch():
    # |startswith normally uses the fast path, but a non-ASCII event value makes
    # starts_with_ignore_case() return None, so matching falls back to the wildcard regex.
    # That fallback must remain a prefix match: "Secあ" starts with "Sec".
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|startswith: Sec
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Secあ"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1378-1396
def test_startswith_multibyte_fallback_no_substring_match():
    # The non-ASCII |startswith regex fallback must be anchored to the start of the value, so
    # a value that merely contains the prefix later on does not match (#1815).
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|startswith: Sec
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "xSecあ"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1399-1405
def test_pipe_pattern_wildcard_asterisk():
    value = wildcard_to_regex(r"*ho*ge*")
    assert value == r"(?i)(.|\a|\f|\t|\n|\r|\v)*ho(.|\a|\f|\t|\n|\r|\v)*ge(.|\a|\f|\t|\n|\r|\v)*"


# tests.rs:1408-1413
def test_pipe_pattern_wildcard_asterisk2():
    value = wildcard_to_regex(r"\*ho\*\*ge\*")
    # The wildcard "\*" represents the literal "*".
    # In regex, "*" must be escaped, so \* is correct.
    assert value == r"(?i)\*ho\*\*ge\*"


# tests.rs:1416-1424
def test_pipe_pattern_wildcard_asterisk3():
    # The wildcard "\\\\*" represents the literal "\\" and the regex ".*".
    # The literal "\\" is escaped, so "\\\\.*" is correct.
    value = wildcard_to_regex(r"\\*ho\\*ge\\*")
    assert (
        value == r"(?i)\\(.|\a|\f|\t|\n|\r|\v)*ho\\(.|\a|\f|\t|\n|\r|\v)*ge\\(.|\a|\f|\t|\n|\r|\v)*"
    )


# tests.rs:1427-1430
def test_pipe_pattern_wildcard_question():
    value = wildcard_to_regex(r"?ho?ge?")
    assert value == r"(?i).ho.ge."


# tests.rs:1433-1436
def test_pipe_pattern_wildcard_question2():
    value = wildcard_to_regex(r"\?ho\?ge\?")
    assert value == r"(?i)\?ho\?ge\?"


# tests.rs:1439-1442
def test_pipe_pattern_wildcard_question3():
    value = wildcard_to_regex(r"\\?ho\\?ge\\?")
    assert value == r"(?i)\\.ho\\.ge\\."


# tests.rs:1445-1448
def test_pipe_pattern_wildcard_backslash():
    # Rust: pipe_pattern_wildcard(r"\\ho\\ge\\") == r"(?i)\\\\ho\\\\ge\\\\". A Python raw string
    # cannot end with a backslash, so the trailing backslashes are appended as a non-raw literal.
    value = wildcard_to_regex(r"\\ho\\ge" + "\\\\")
    assert value == r"(?i)\\\\ho\\\\ge" + "\\\\\\\\"


# tests.rs:1451-1457
def test_pipe_pattern_wildcard_mixed():
    value = wildcard_to_regex(r"\\*\****\*\\*")
    assert (
        value
        == r"(?i)\\(.|\a|\f|\t|\n|\r|\v)*\*(.|\a|\f|\t|\n|\r|\v)*(.|\a|\f|\t|\n|\r|\v)*(.|\a|\f|\t|\n|\r|\v)*\*\\(.|\a|\f|\t|\n|\r|\v)*"
    )


# tests.rs:1460-1466
def test_pipe_pattern_wildcard_many_backslashes():
    # Rust: pipe_pattern_wildcard(r"\\\*ho\\\*ge\\\") == r"(?i)\\\\(.|\a|\f|\t|\n|\r|\v)*ho\\\\(.|\a|\f|\t|\n|\r|\v)*ge\\\\\\".
    # Both strings end with backslashes, which a Python raw string cannot, so the tails are
    # appended as non-raw literals (three and six backslashes respectively).
    value = wildcard_to_regex(r"\\\*ho\\\*ge" + "\\\\\\")
    assert value == r"(?i)\\\\(.|\a|\f|\t|\n|\r|\v)*ho\\\\(.|\a|\f|\t|\n|\r|\v)*ge" + "\\\\\\\\\\\\"


# tests.rs:1469-1486
def test_grep_match():
    # A selection written as a bare list (no field name) performs a grep-style match against
    # the whole record.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                - 4103
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, True)


# tests.rs:1489-1507
def test_grep_not_match():
    # A grep-style match (bare list, no field name) does not match a record that does not
    # contain the value.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                - 4104
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1510-1528
def test_detect_value_keyword():
    # Verify that the "value:" keyword form matches exactly.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    value: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1531-1550
def test_notdetect_value_keyword():
    # Verify that the "value:" keyword form is an exact match: a similar but different
    # value (rule "Securiteen" vs record "Security") does not match.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel:
                    value: Securiteen
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1553-1569
def test_endswith_field():
    # Verify that endswithfield is correctly detected.
    rule_str = r"""
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "rity" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1572-1588
def test_endswith_field2():
    # Verify that endswithfield is correctly detected.
    rule_str = r"""
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1591-1607
def test_endswith_field_caseinsensitive():
    # Verify that endswithfield detects case-insensitively.
    rule_str = r"""
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "iTy" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1610-1626
def test_endswith_field_caseinsensitive2():
    # Verify that endswithfield detects case-insensitively.
    rule_str = r"""
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "SecuriTy", "Computer": "ity" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1629-1645
def test_endswith_field_notdetect():
    # Patterns correctly not detected by endswithfield.
    rule_str = r"""
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "rity", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1648-1664
def test_endswith_field_notdetect2():
    # Patterns correctly not detected by endswithfield.
    rule_str = r"""
        detection:
            selection:
                Channel|endswithfield: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Sec" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1667-1683
def test_eq_field_ref():
    # Verify that fieldref is correctly detected.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1686-1701
def test_eq_field_ref_notdetect():
    # Patterns that fieldref cannot detect.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:1704-1720
def test_eq_field_ref_endswith():
    # Verify that fieldref is correctly detected.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|endswith: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "rity" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1723-1738
def test_eq_field_ref_notdetect_endswith():
    # Patterns that fieldref cannot detect.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:1741-1757
def test_eq_field_ref_startswith():
    # Verify that fieldref is correctly detected.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|startswith: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Sec" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1760-1775
def test_eq_field_ref_notdetect_startswith():
    # Patterns that fieldref cannot detect.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|startswith: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:1778-1794
def test_eq_field_ref_contains():
    # Verify that fieldref is correctly detected.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|contains: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "cur" }},
            "Event_attributes": {"xmlns": "http://sc-allhemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1797-1812
def test_eq_field_ref_notdetect_contains():
    # Patterns that fieldref cannot detect.
    rule_str = r"""
        detection:
            selection:
                Channel|fieldref|contains: Computer
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer": "Powershell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# tests.rs:1815-1831
def test_neq_detect():
    # `neq` matches when the field value is different from the specified value.
    rule_str = r"""
        detection:
            selection:
                Channel|neq: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "PowerShell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1834-1850
def test_neq_notdetect():
    # `neq` does not match when the field value equals the specified value.
    rule_str = r"""
        detection:
            selection:
                Channel|neq: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1853-1870
def test_neq_case_insensitive_notdetect():
    # Like the plain value match, `neq` equality is case-insensitive, so "security" == "Security"
    # and therefore `neq` does not match.
    rule_str = r"""
        detection:
            selection:
                Channel|neq: security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1873-1890
def test_neq_missing_field_detect():
    # A missing field is treated as different from the value (consistent with `not` in condition),
    # so `neq` matches.
    rule_str = r"""
        detection:
            selection:
                Channel|neq: Security
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103 }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)


# tests.rs:1893-1909
def test_neq_wildcard_notdetect():
    # Wildcards still apply to the value being negated: "Sec*" matches "Security", so `neq` does not match.
    rule_str = r"""
        detection:
            selection:
                Channel|neq: Sec*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# tests.rs:1912-1928
def test_neq_wildcard_detect():
    # "Sec*" does not match "PowerShell", so `neq` matches.
    rule_str = r"""
        detection:
            selection:
                Channel|neq: Sec*
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "PowerShell" }},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, True)
