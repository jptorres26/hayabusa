"""Port of the ``mod tests`` of ``src/detections/rule/rulenode.rs`` (lines 476-1165)."""

from __future__ import annotations

from helpers_rules import (
    check_select,
    create_rule,
    dummy_context,
    dummy_eventkey_alias,
    init_rule,
    make_rec_info,
)


# rulenode.rs:545-563
def test_detect_dotkey():
    # Verify that a key written as a dot-joined path (instead of an alias) is detected
    # correctly.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Event.System.Computer: DESKTOP-ICHIICHI
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, True)


# rulenode.rs:565-583
def test_notdetect_dotkey():
    # Verify that a record which should not be detected is not detected when the key is a
    # dot-joined path instead of an alias.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Event.System.Computer: DESKTOP-ICHIICHIN
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""
    check_select(rule_str, record_json_str, False)


# rulenode.rs:585-604
def test_notdetect_differentkey():
    # Verify that a record is not detected when the value of the rule's field (here the
    # aliased key Channel) differs from the value in the record.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: NOTDETECT
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {"System": {"EventID": 4103, "Channel": "Security", "Computer":"DESKTOP-ICHIICHI"}},
            "Event_attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        }"""

    check_select(rule_str, record_json_str, False)


# rulenode.rs:606-678
def test_detect_attribute():
    # Test for cases where JSON is parsed in a special way when a value exists in the
    # attribute part of an XML tag.
    # The original XML looks like the following, and this is a test to detect Name or Guid
    # in the Provider tag.
    #         - <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    #         - <System>
    #           <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    #           <EventID>4672</EventID>
    #           <Version>0</Version>
    #           <Level>0</Level>
    #           <Task>12548</Task>
    #           <Opcode>0</Opcode>
    #           <Keywords>0x8020000000000000</Keywords>
    #           <TimeCreated SystemTime="2021-05-12T13:33:08.0144343Z" />
    #           <EventRecordID>244666</EventRecordID>
    #           <Correlation ActivityID="{0188dd7a-447d-000c-82dd-88017d44d701}" />
    #           <Execution ProcessID="1172" ThreadID="22352" />
    #           <Channel>Security</Channel>
    #           <Security />
    #           </System>
    #         - <EventData>
    #           <Data Name="SubjectUserName">SYSTEM</Data>
    #           <Data Name="SubjectDomainName">NT AUTHORITY</Data>
    #           <Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege SeTcbPrivilege SeSecurityPrivilege SeTakeOwnershipPrivilege SeLoadDriverPrivilege SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege SeAuditPrivilege SeSystemEnvironmentPrivilege SeImpersonatePrivilege SeDelegateSessionUserImpersonatePrivilege</Data>
    #           </EventData>
    #           </Event>

    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4797
                Event.System.Provider_attributes.Guid: 54849625-5478-4994-A5BA-3E3B0328C30D
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {
              "System": {
                "Channel": "Security",
                "Correlation_attributes": {
                  "ActivityID": "0188DD7A-447D-000C-82DD-88017D44D701"
                },
                "EventID": 4797,
                "EventRecordID": 239219,
                "Execution_attributes": {
                  "ProcessID": 1172,
                  "ThreadID": 23236
                },
                "Keywords": "0x8020000000000000",
                "Level": 0,
                "Opcode": 0,
                "Provider_attributes": {
                  "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
                  "Name": "Microsoft-Windows-Security-Auditing"
                },
                "Security": null,
                "Task": 13824,
                "TimeCreated_attributes": {
                  "SystemTime": "2021-05-12T09:39:19.828403Z"
                },
                "Version": 0
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
          }"""
    check_select(rule_str, record_json_str, True)


# rulenode.rs:680-726
def test_notdetect_attribute():
    # Verify a case where a value in an XML tag attribute should not be detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4797
                Event.System.Provider_attributes.Guid: 54849625-5478-4994-A5BA-3E3B0328C30DSS
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {
              "System": {
                "Channel": "Security",
                "Correlation_attributes": {
                  "ActivityID": "0188DD7A-447D-000C-82DD-88017D44D701"
                },
                "EventID": 4797,
                "EventRecordID": 239219,
                "Execution_attributes": {
                  "ProcessID": 1172,
                  "ThreadID": 23236
                },
                "Keywords": "0x8020000000000000",
                "Level": 0,
                "Opcode": 0,
                "Provider_attributes": {
                  "Guid": "54849625-5478-4994-A5BA-3E3B0328C30D",
                  "Name": "Microsoft-Windows-Security-Auditing"
                },
                "Security": null,
                "Task": 13824,
                "TimeCreated_attributes": {
                  "SystemTime": "2021-05-12T09:39:19.828403Z"
                },
                "Version": 0
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
          }"""
    check_select(rule_str, record_json_str, False)


# rulenode.rs:728-783
def test_detect_eventdata():
    # In a special XML format pattern, there is a tag called EventData, and the value that
    # acts as the field key comes in the Name= attribute.
    # - <EventData>
    #   <Data Name="SubjectUserSid">S-1-5-21-2673273881-979819022-3746999991-1001</Data>
    #   <Data Name="SubjectUserName">takai</Data>
    #   <Data Name="SubjectDomainName">DESKTOP-ICHIICH</Data>
    #   <Data Name="SubjectLogonId">0x312cd</Data>
    #   <Data Name="Workstation">DESKTOP-ICHIICH</Data>
    #   <Data Name="TargetUserName">Administrator</Data>
    #   <Data Name="TargetDomainName">DESKTOP-ICHIICH</Data>
    #   </EventData>

    # In that case, the JSON produced by the event parser looks like the following, so test
    # that it can be correctly detected.
    #         {
    #             "Event": {
    #               "EventData": {
    #                 "TargetDomainName": "TEST-DOMAIN",
    #                 "Workstation": "TEST WorkStation"
    #                 "TargetUserName": "ichiichi11",
    #               },
    #             }
    #         }

    rule_str = r"""
        enabled: true
        detection:
            selection:
                Event.EventData.Workstation: 'TEST WorkStation'
                Event.EventData.TargetUserName: ichiichi11
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {
              "EventData": {
                "Workstation": "TEST WorkStation",
                "TargetUserName": "ichiichi11"
              },
              "System": {
                "Channel": "Security",
                "EventID": 4103,
                "EventRecordID": 239219,
                "Security": null
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
        }
        """
    check_select(rule_str, record_json_str, True)


# rulenode.rs:785-818
def test_detect_eventdata2():
    # Verify that an EventData field can be matched by its bare name: keys without an alias
    # or dots fall back to Event.EventData.<key>.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4103
                TargetUserName: ichiichi11
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {
              "EventData": {
                "Workstation": "TEST WorkStation",
                "TargetUserName": "ichiichi11"
              },
              "System": {
                "Channel": "Security",
                "EventID": 4103,
                "EventRecordID": 239219,
                "Security": null
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
        }
        """
    check_select(rule_str, record_json_str, True)


# rulenode.rs:820-852
def test_notdetect_eventdata():
    # Patterns where EventData is not detected.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 4103
                TargetUserName: ichiichi12
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {
              "EventData": {
                "Workstation": "TEST WorkStation",
                "TargetUserName": "ichiichi11"
              },
              "System": {
                "Channel": "Security",
                "EventID": 4103,
                "EventRecordID": 239219,
                "Security": null
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
        }
        """
    check_select(rule_str, record_json_str, False)


# rulenode.rs:854-907
def test_detect_special_eventdata():
    # A further special case of EventData beyond the above test case, where there is no Name
    # key inside the Data tag as shown below.
    # For this reason, only the EventData key receives special handling in the rule file.
    # Currently, this case has only been confirmed with the downgrade_attack.yml rule.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 403
                EventData|re: '[\s\S]*EngineVersion=2\.0[\s\S]*'
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {
              "EventData": {
                "Binary": null,
                "Data": [
                  "Stopped",
                  "Available",
                  "\tNewEngineState=Stopped\n\tPreviousEngineState=Available\n\n\tSequenceNumber=10\n\n\tHostName=ConsoleHost\n\tHostVersion=2.0\n\tHostId=5cbb33bf-acf7-47cc-9242-141cd0ba9f0c\n\tEngineVersion=2.0\n\tRunspaceId=c6e94dca-0daf-418c-860a-f751a9f2cbe1\n\tPipelineId=\n\tCommandName=\n\tCommandType=\n\tScriptName=\n\tCommandPath=\n\tCommandLine="
                ]
              },
              "System": {
                "Channel": "Windows PowerShell",
                "Computer": "DESKTOP-ST69BPO",
                "EventID": 403,
                "EventID_attributes": {
                  "Qualifiers": 0
                },
                "EventRecordID": 730,
                "Keywords": "0x80000000000000",
                "Level": 4,
                "Provider_attributes": {
                  "Name": "PowerShell"
                },
                "Security": null,
                "Task": 4,
                "TimeCreated_attributes": {
                  "SystemTime": "2021-01-28T10:40:54.946866Z"
                }
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
          }
        """

    check_select(rule_str, record_json_str, True)


# rulenode.rs:909-962
def test_notdetect_special_eventdata():
    # A further special case of EventData beyond the above test case, where there is no Name
    # key inside the Data tag as shown below.
    # For this reason, only the EventData key receives special handling in the rule file.
    # Currently, this case has only been confirmed with the downgrade_attack.yml rule.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                EventID: 403
                EventData: '[\s\S]*EngineVersion=3.0[\s\S]*'
        details: 'command=%CommandLine%'
        """

    record_json_str = r"""
        {
            "Event": {
              "EventData": {
                "Binary": null,
                "Data": [
                  "Stopped",
                  "Available",
                  "\tNewEngineState=Stopped\n\tPreviousEngineState=Available\n\n\tSequenceNumber=10\n\n\tHostName=ConsoleHost\n\tHostVersion=2.0\n\tHostId=5cbb33bf-acf7-47cc-9242-141cd0ba9f0c\n\tEngineVersion=2.0\n\tRunspaceId=c6e94dca-0daf-418c-860a-f751a9f2cbe1\n\tPipelineId=\n\tCommandName=\n\tCommandType=\n\tScriptName=\n\tCommandPath=\n\tCommandLine="
                ]
              },
              "System": {
                "Channel": "Windows PowerShell",
                "Computer": "DESKTOP-ST69BPO",
                "EventID": 403,
                "EventID_attributes": {
                  "Qualifiers": 0
                },
                "EventRecordID": 730,
                "Keywords": "0x80000000000000",
                "Level": 4,
                "Provider_attributes": {
                  "Name": "PowerShell"
                },
                "Security": null,
                "Task": 4,
                "TimeCreated_attributes": {
                  "SystemTime": "2021-01-28T10:40:54.946866Z"
                }
              }
            },
            "Event_attributes": {
              "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
            }
          }
        """

    check_select(rule_str, record_json_str, False)


# rulenode.rs:964-998
def test_use_strfeature_in_or_node():
    # Test that startswith can also be used within an OR node (a list of values).
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7040
                param1: 'Windows Event Log'
                param2|startswith:
                    - "disa"
                    - "aut"
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


# rulenode.rs:1000-1021
def test_detect_undefined_rule_option():
    # Test that a warning is issued when an unknown string option is written in a rule.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel|failed: Security
                EventID: 0
        details: 'Rule parse test'
        """
    _rule, errors = init_rule(rule_str)

    assert errors == [
        "An unknown pipe element was specified. key:detection -> selection -> Channel|failed"
    ]


# rulenode.rs:1023-1051
def test_neq_on_keyless_all_is_rejected():
    # `|all|neq` has no field to negate: the keyless `|all` whole-record path only handles an
    # exact `|all` key, so this combination must be rejected at rule load rather than silently
    # matching every record (regression test for the Copilot review on #1800).
    rule_str = r"""
        enabled: true
        detection:
            selection:
                '|all|neq':
                    - foo
                    - bar
        details: 'Rule parse test'
        """
    _rule, result = init_rule(rule_str)
    assert result, "expected `|all|neq` to be rejected at init"
    assert any("neq" in msg and "|all" in msg for msg in result), (
        "error should explain the neq/|all conflict"
    )


# rulenode.rs:1053-1068
def test_detect_not_defined_selection():
    # Test that an error is returned when the detection node has no content.
    rule_str = r"""
        enabled: true
        detection:
        details: 'Rule parse test'
        """
    _rule, errors = init_rule(rule_str)

    assert errors == ["Detection node was not found."]


# rulenode.rs:1070-1124
def test_use_allfeature_():
    # Test that when the |all modifier is given, the listed values are combined with AND.
    rule_str = r"""
        enabled: true
        detection:
            selection:
                Channel: 'System'
                EventID: 7040
                param1: 'Windows Event Log'
                param2|contains|all:
                    - "star"
                    - "aut"
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

    # A record that should not match: param2 contains "aut" but not "star", so contains|all
    # fails.
    record_json_str2 = r"""
        {
          "Event": {
            "System": {
              "EventID": 7040,
              "Channel": "System"
            },
            "EventData": {
              "param1": "Windows Event Log",
              "param2": "auts"
            }
          },
          "Event_attributes": {
            "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
          }
        }"""

    check_select(rule_str, record_json_str, True)
    check_select(rule_str, record_json_str2, False)


# rulenode.rs:1126-1164 — test helper that verifies the number of records accumulated for the
# count aggregation. (Unused by any test in the Rust module as well; kept for parity.)
def _check_count(rule_str: str, record_str: str, key: str, expect_count: int) -> None:
    rule_node = create_rule(rule_str)
    _init = rule_node.init(dummy_context())

    recinfo = make_rec_info(rule_node, record_str)
    result = rule_node.select(recinfo, dummy_eventkey_alias())
    assert rule_node.detection.aggregation_condition is not None
    assert result
    assert len(rule_node.countdata[key]) == expect_count
