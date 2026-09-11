# Differential report — sample-evtx / all

- rules loaded: 4645 (parse errors 0); index {'channel+eid': 4250, 'channel': 174, 'eid': 215, 'unindexed': 6}
- files: 599, events: 47699, events with hits: 23550
- rule evaluations: 17340672 (364 per event)
- wall clock: rules 5.1s + scan 122.6s; events/s (scan only): 389

## Record detections: golden 32444, ours 32444
- matched: 32444 (100.00% of golden)
- missing (golden only): 0
- extra (ours only): 0 (0.00% of golden)

## Aggregation detections: golden 3, ours 3; matched 3

## Missing by rule (top 40)

## Extra by rule (top 40)

## Samples

## Render jsonl / super-verbose: 32447 lines in 16.1s (golden 32447)
- identical lines: 32433; only in golden: 14; only in ours: 14; byte-identical order: False
- golden: { "Timestamp":"2020-07-11T12:58:32.242577Z","RuleTitle":"Failed DNS Zone Transfer","Level":"med","Computer":"rootdc1.offsec.lan","Channel":"DNS-Svr","EventID":6004,"RuleAuthor":"Zach Mathis","Status":"test","RecordID":341,"Details":{"Binary":"","Name":"DNS_EVENT_BAD_ZONE_TRANSFER_REQUEST","param1":"10.23.23.9","param2":"non-existing.lan."},"ExtraFieldInfo":{},"MitreTactics":["Recon"],"MitreTags":[
- ours:   { "Timestamp":"2020-07-11T12:58:32.242577Z","RuleTitle":"Failed DNS Zone Transfer","Level":"med","Computer":"rootdc1.offsec.lan","Channel":"DNS-Svr","EventID":6004,"RuleAuthor":"Zach Mathis","Status":"test","RecordID":341,"Details":{"Name":"DNS_EVENT_BAD_ZONE_TRANSFER_REQUEST","param1":"10.23.23.9","param2":"non-existing.lan."},"ExtraFieldInfo":{},"MitreTactics":["Recon"],"MitreTags":["T1590.002"]
- golden: { "Timestamp":"2020-07-11T12:58:40.280466Z","RuleTitle":"Failed DNS Zone Transfer","Level":"med","Computer":"rootdc1.offsec.lan","Channel":"DNS-Svr","EventID":6004,"RuleAuthor":"Zach Mathis","Status":"test","RecordID":342,"Details":{"Binary":"","Name":"DNS_EVENT_BAD_ZONE_TRANSFER_REQUEST","param1":"10.23.23.9","param2":"google.com."},"ExtraFieldInfo":{},"MitreTactics":["Recon"],"MitreTags":["T1590
- ours:   { "Timestamp":"2020-07-11T12:58:40.280466Z","RuleTitle":"Failed DNS Zone Transfer","Level":"med","Computer":"rootdc1.offsec.lan","Channel":"DNS-Svr","EventID":6004,"RuleAuthor":"Zach Mathis","Status":"test","RecordID":342,"Details":{"Name":"DNS_EVENT_BAD_ZONE_TRANSFER_REQUEST","param1":"10.23.23.9","param2":"google.com."},"ExtraFieldInfo":{},"MitreTactics":["Recon"],"MitreTags":["T1590.002"],"Prov
- golden: { "Timestamp":"2020-07-11T12:58:57.451062Z","RuleTitle":"Failed DNS Zone Transfer","Level":"med","Computer":"rootdc1.offsec.lan","Channel":"DNS-Svr","EventID":6004,"RuleAuthor":"Zach Mathis","Status":"test","RecordID":343,"Details":{"Binary":"","Name":"DNS_EVENT_BAD_ZONE_TRANSFER_REQUEST","param1":"10.23.23.9","param2":"hacking-zone.lan."},"ExtraFieldInfo":{},"MitreTactics":["Recon"],"MitreTags":[
- ours:   { "Timestamp":"2020-07-11T12:58:57.451062Z","RuleTitle":"Failed DNS Zone Transfer","Level":"med","Computer":"rootdc1.offsec.lan","Channel":"DNS-Svr","EventID":6004,"RuleAuthor":"Zach Mathis","Status":"test","RecordID":343,"Details":{"Name":"DNS_EVENT_BAD_ZONE_TRANSFER_REQUEST","param1":"10.23.23.9","param2":"hacking-zone.lan."},"ExtraFieldInfo":{},"MitreTactics":["Recon"],"MitreTags":["T1590.002"]
- golden: { "Timestamp":"2021-12-16T10:25:30.415637900Z","RuleTitle":"RDP Logon","Level":"info","Computer":"fs03vuln.offsec.lan","Channel":"RDS-RCM","EventID":1149,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2025-02-10","Status":"stable","RecordID":99456,"Details":{"TgtUser":"admmig","Domain":"n/a","SrcIP":"10.23.123.11"},"ExtraFieldInfo":{},"MitreTactics":["LatMov","InitAccess"],"OtherTags":["RDP"],"Pro
- ours:   { "Timestamp":"2021-12-16T10:25:30.415637900Z","RuleTitle":"RDP Logon","Level":"info","Computer":"fs03vuln.offsec.lan","Channel":"RDS-RCM","EventID":1149,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2025-02-10","Status":"stable","RecordID":99456,"Details":{"TgtUser":"admmig","Domain":"","SrcIP":"10.23.123.11"},"ExtraFieldInfo":{},"MitreTactics":["LatMov","InitAccess"],"OtherTags":["RDP"],"Provid
- golden: { "Timestamp":"2021-12-16T10:25:32.351835800Z","RuleTitle":"RDP Logon","Level":"info","Computer":"rootdc1.offsec.lan","Channel":"RDS-RCM","EventID":1149,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2025-02-10","Status":"stable","RecordID":6433,"Details":{"TgtUser":"admmig","Domain":"n/a","SrcIP":"10.23.123.11"},"ExtraFieldInfo":{},"MitreTactics":["LatMov","InitAccess"],"OtherTags":["RDP"],"Provi
- ours:   { "Timestamp":"2021-12-16T10:25:32.351835800Z","RuleTitle":"RDP Logon","Level":"info","Computer":"rootdc1.offsec.lan","Channel":"RDS-RCM","EventID":1149,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2025-02-10","Status":"stable","RecordID":6433,"Details":{"TgtUser":"admmig","Domain":"","SrcIP":"10.23.123.11"},"ExtraFieldInfo":{},"MitreTactics":["LatMov","InitAccess"],"OtherTags":["RDP"],"Provider
- golden: { "Timestamp":"2021-12-16T10:25:32.367518Z","RuleTitle":"RDP Logon","Level":"info","Computer":"mssql01.offsec.lan","Channel":"RDS-RCM","EventID":1149,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2025-02-10","Status":"stable","RecordID":2858,"Details":{"TgtUser":"admmig","Domain":"n/a","SrcIP":"10.23.123.11"},"ExtraFieldInfo":{},"MitreTactics":["LatMov","InitAccess"],"OtherTags":["RDP"],"Provider
- ours:   { "Timestamp":"2021-12-16T10:25:32.367518Z","RuleTitle":"RDP Logon","Level":"info","Computer":"mssql01.offsec.lan","Channel":"RDS-RCM","EventID":1149,"RuleAuthor":"Zach Mathis","RuleModifiedDate":"2025-02-10","Status":"stable","RecordID":2858,"Details":{"TgtUser":"admmig","Domain":"","SrcIP":"10.23.123.11"},"ExtraFieldInfo":{},"MitreTactics":["LatMov","InitAccess"],"OtherTags":["RDP"],"Provider":"
