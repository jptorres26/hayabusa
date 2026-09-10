# Differential report — sample-evtx / all

- rules loaded: 4645 (parse errors 0); index {'channel+eid': 4250, 'channel': 174, 'eid': 215, 'unindexed': 6}
- files: 599, events: 47699, events with hits: 23550
- rule evaluations: 17340672 (364 per event)
- wall clock: rules 3.8s + scan 86.0s; events/s (scan only): 554

## Record detections: golden 32444, ours 32444
- matched: 32444 (100.00% of golden)
- missing (golden only): 0
- extra (ours only): 0 (0.00% of golden)

## Aggregation detections: golden 3, ours 3; matched 3

## Missing by rule (top 40)

## Extra by rule (top 40)

## Samples

## Render jsonl / super-verbose: 32447 lines in 13.8s (golden 32447)
- identical lines: 32332; only in golden: 115; only in ours: 115; byte-identical order: False
- golden: { "Timestamp":"2013-10-23T16:16:56.406250Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":117,"Details":{"DeviceID":"ROOT\\MS_NDISWANBH\\0000","Provider":"Microsoft","Description":"WAN Miniport (Network Monitor)","Status":"0x0"},"ExtraFieldInfo":{
- ours:   { "Timestamp":"2013-10-23T16:16:56.406250Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":117,"Details":{"DeviceID":"ROOT\\MS_NDISWANBH\\0000","Provider":"Microsoft","Description":"WAN Miniport (Network Monitor)","Status":"0x0"},"ExtraFieldInfo":{
- golden: { "Timestamp":"2013-10-23T16:16:57.171875Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":119,"Details":{"DeviceID":"ROOT\\MS_AGILEVPNMINIPORT\\0000","Provider":"Microsoft","Description":"WAN Miniport (IKEv2)","Status":"0x0"},"ExtraFieldInfo":{"Dr
- ours:   { "Timestamp":"2013-10-23T16:16:57.171875Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":119,"Details":{"DeviceID":"ROOT\\MS_AGILEVPNMINIPORT\\0000","Provider":"Microsoft","Description":"WAN Miniport (IKEv2)","Status":"0x0"},"ExtraFieldInfo":{"Dr
- golden: { "Timestamp":"2013-10-23T16:16:58.843750Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":122,"Details":{"DeviceID":"ROOT\\MS_NDISWANIP\\0000","Provider":"Microsoft","Description":"WAN Miniport (IP)","Status":"0x0"},"ExtraFieldInfo":{"DriverName":
- ours:   { "Timestamp":"2013-10-23T16:16:58.843750Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":122,"Details":{"DeviceID":"ROOT\\MS_NDISWANIP\\0000","Provider":"Microsoft","Description":"WAN Miniport (IP)","Status":"0x0"},"ExtraFieldInfo":{"DriverVersio
- golden: { "Timestamp":"2013-10-23T16:16:59.968750Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":124,"Details":{"DeviceID":"ROOT\\MS_L2TPMINIPORT\\0000","Provider":"Microsoft","Description":"WAN Miniport (L2TP)","Status":"0x0"},"ExtraFieldInfo":{"DriverN
- ours:   { "Timestamp":"2013-10-23T16:16:59.968750Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":124,"Details":{"DeviceID":"ROOT\\MS_L2TPMINIPORT\\0000","Provider":"Microsoft","Description":"WAN Miniport (L2TP)","Status":"0x0"},"ExtraFieldInfo":{"DriverV
- golden: { "Timestamp":"2013-10-23T16:17:01.140625Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":127,"Details":{"DeviceID":"ROOT\\MS_NDISWANIPV6\\0000","Provider":"Microsoft","Description":"WAN Miniport (IPv6)","Status":"0x0"},"ExtraFieldInfo":{"DriverNa
- ours:   { "Timestamp":"2013-10-23T16:17:01.140625Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":127,"Details":{"DeviceID":"ROOT\\MS_NDISWANIPV6\\0000","Provider":"Microsoft","Description":"WAN Miniport (IPv6)","Status":"0x0"},"ExtraFieldInfo":{"DriverVe
- golden: { "Timestamp":"2013-10-23T16:17:02.656250Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":129,"Details":{"DeviceID":"ROOT\\MS_PPPOEMINIPORT\\0000","Provider":"Microsoft","Description":"WAN Miniport (PPPOE)","Status":"0x0"},"ExtraFieldInfo":{"Drive
- ours:   { "Timestamp":"2013-10-23T16:17:02.656250Z","RuleTitle":"New Non-USB PnP Device","Level":"info","Computer":"37L4247D28-05","Channel":"Sys","EventID":20001,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2022-06-21","Status":"stable","RecordID":129,"Details":{"DeviceID":"ROOT\\MS_PPPOEMINIPORT\\0000","Provider":"Microsoft","Description":"WAN Miniport (PPPOE)","Status":"0x0"},"ExtraFieldInfo":{"Drive
