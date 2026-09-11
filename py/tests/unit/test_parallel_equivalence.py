"""A parallel scan must produce exactly what a single-process one does.

The full-corpus check lives in the differential harness; this is the fast version that runs in
the unit suite, on a rule set and record set built here, so a regression in the worker protocol
(rows, spooled rows, or the aggregation merge) is caught without the Hayabusa oracle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest  # noqa: F401  (kept for the fixture decorator)

from hayabusa_py.engine.detect import Detector, load_rule_set
from hayabusa_py.engine.parallel import WorkerSetup, merge_countdata, scan_jobs, split_jobs
from hayabusa_py.engine.timeutil import TimeFormatOptions
from hayabusa_py.output.config import OutputConfig
from hayabusa_py.output.render import render
from hayabusa_py.output.spool import merge_spools
from hayabusa_py.output.writers import render_to_string, sort_key
from hayabusa_py.rules.config import RulesConfig
from hayabusa_py.rules.loader import RuleFilterOptions

RULES = {
    "logon.yml": """
title: A network logon
id: 11111111-1111-1111-1111-111111111111
status: test
level: medium
author: test
date: 2026-01-01
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4624
        LogonType: 3
    condition: selection
details: 'user: %TargetUserName% ¦ type: %LogonType%'
""",
    "process.yml": """
title: A suspicious process
id: 22222222-2222-2222-2222-222222222222
status: test
level: high
author: test
date: 2026-01-01
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4688
        NewProcessName|endswith: '\\\\powershell.exe'
    condition: selection
details: 'process: %NewProcessName%'
""",
    "burst.yml": """
title: Many logons from one host
id: 33333333-3333-3333-3333-333333333333
status: test
level: low
author: test
date: 2026-01-01
logsource:
    product: windows
    service: security
detection:
    selection:
        Channel: Security
        EventID: 4624
    timeframe: 1h
    condition: selection | count() by Computer > 3
details: 'count: %Computer%'
""",
}


def record(index: int, event_id: int, computer: str) -> dict:
    return {
        "Event": {
            "System": {
                "Channel": "Security",
                "EventID": event_id,
                "EventRecordID": index,
                "Computer": computer,
                "Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"},
                "TimeCreated_attributes": {"SystemTime": f"2026-01-01T00:{index % 60:02d}:00.000000Z"},
            },
            "EventData": {
                "TargetUserName": f"user{index % 4}",
                "LogonType": 3,
                "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
            },
        }
    }


@pytest.fixture
def workspace(tmp_path: Path):  # noqa: ANN201
    rules_dir = tmp_path / "rules"
    (rules_dir / "config").mkdir(parents=True)
    for name, text in RULES.items():
        (rules_dir / name).write_text(text, encoding="utf-8")
    # the loader needs its config files to exist, even if empty
    for name in ("eventkey_alias.txt", "exclude_rules.txt", "noisy_rules.txt", "windash_characters.txt"):
        source = Path(__file__).resolve().parents[1] / "fixtures" / "config" / name
        target = rules_dir / "config" / name
        target.write_text(source.read_text(encoding="utf-8") if source.exists() else "", encoding="utf-8")

    records_dir = tmp_path / "records"
    records_dir.mkdir()
    files = []
    for part in range(4):
        path = records_dir / f"part{part}.jsonl"
        with open(path, "w", encoding="utf-8") as handle:
            for index in range(part * 25, part * 25 + 25):
                event_id = 4624 if index % 2 == 0 else 4688
                handle.write(json.dumps(record(index, event_id, f"PC{index % 3}")) + "\n")
        files.append(path)
    return rules_dir, files


def scan(rules_dir: Path, config_dir: Path, files: list[Path], workers: int, spool_dir: Path | None) -> str:
    config = RulesConfig.load(rules_dir / "config", config_dir / "expand")
    options = RuleFilterOptions()
    rule_set = load_rule_set(rules_dir, config, options)
    assert len(rule_set.rules) == 3, "the test rule set did not load"
    out_cfg = OutputConfig.load(
        config_dir,
        rules_dir / "config",
        None,
        time_format=TimeFormatOptions(utc=True, iso_8601=True),
        json_timeline=True,
        output_to_file=True,
    )
    detector = Detector(rule_set, config)
    setup = WorkerSetup(
        rules_path=str(rules_dir),
        rules_config_dir=str(rules_dir / "config"),
        config_dir=str(config_dir),
        expand_dir=str(config_dir / "expand"),
        filter_options=options,
        time_format=TimeFormatOptions(utc=True, iso_8601=True),
        json_timeline=True,
        reader="json",
        output_to_file=True,
        spool_dir=str(spool_dir) if spool_dir else "",
        spool_flush_rows=7,  # tiny, so the merge is exercised over many runs
    )
    jobs = split_jobs([(str(path), path.name) for path in files], workers=workers)
    rows = []
    spool_paths: list[Path] = []
    fragments = []
    for result in scan_jobs(jobs, setup, workers=workers):
        rows.extend(result.rows)
        spool_paths.extend(Path(path) for path in result.spool_paths)
        fragments.append(result.countdata)
        detector.stats.merge(result.stats)
    merge_countdata(rule_set.rules, fragments)
    rows.extend(render(det, out_cfg, config.eventkey_alias) for det in detector.finish())
    if spool_paths:
        rows.extend(merge_spools(spool_paths))
    rows.sort(key=sort_key)
    return render_to_string(rows, "jsonl")


CONFIG_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "config-min"


def test_a_parallel_scan_matches_a_single_process_one(workspace, tmp_path: Path) -> None:
    rules_dir, files = workspace
    config_dir = CONFIG_DIR

    single = scan(rules_dir, config_dir, files, workers=1, spool_dir=None)
    parallel = scan(rules_dir, config_dir, files, workers=2, spool_dir=None)
    spooled = scan(rules_dir, config_dir, files, workers=2, spool_dir=tmp_path / "spool")

    assert single, "the scan produced nothing, so the comparison proves nothing"
    assert parallel == single
    assert spooled == single
    # the aggregation rule must fire, so the countdata merge is actually covered
    assert "Many logons from one host" in single
