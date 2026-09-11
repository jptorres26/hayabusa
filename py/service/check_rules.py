"""Gate a candidate rule set before it goes live.

Detection rules are updated on a schedule, from a repository that moves with Hayabusa's own
engine. A rule set that uses a modifier this engine does not implement, or that simply fails to
parse, would silently reduce coverage -- the scan would still "succeed", with fewer detections.
So the update job runs this first and only swaps the rules in when it passes.

    python -m service.check_rules --rules <candidate> --config <config> [--compare-to <live>]
                                  [--sample <records.jsonl> --min-detections N]

Exit status is 0 when the set is fit to install and 1 when it is not; the reasons are printed
either way, and ``--json`` emits the same as a machine-readable report.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from hayabusa_py.engine.detect import Detector, load_rule_set
from hayabusa_py.engine.matchers import Pipe
from hayabusa_py.evtx.jsonl_reader import iter_jsonl_records
from hayabusa_py.rules.config import RulesConfig
from hayabusa_py.rules.loader import RuleFilterOptions

# A rule set that loses more than this share of its rules against the live set is treated as
# broken rather than merely changed: upstream churn is gradual, a cliff is a mistake.
MAX_SHRINK = 0.10
MAX_PARSE_ERROR_RATE = 0.02


def inspect(rules_dir: Path, config_dir: Path) -> dict[str, Any]:
    rules_config_dir = rules_dir / "config"
    config = RulesConfig.load(rules_config_dir, config_dir / "expand")
    log_lines: list[str] = []
    rule_set = load_rule_set(rules_dir, config, RuleFilterOptions(), log_lines.append)
    unsupported: Counter[str] = Counter()
    for line in log_lines:
        # The loader reports an unknown modifier by quoting the whole selection key; pick the
        # modifier out of it, so the report names the missing feature rather than only the rule.
        for name in _unknown_modifiers(line):
            unsupported[name] += 1
    return {
        "rules_dir": str(rules_dir),
        "loaded": len(rule_set.rules),
        "parse_errors": rule_set.parse_error_count,
        "unsupported_modifiers": dict(unsupported.most_common()),
        "log_sample": log_lines[:20],
        "config": config,
        "rule_set": rule_set,
    }


_KNOWN_PIPES = {pipe.value for pipe in Pipe}


def _unknown_modifiers(line: str) -> list[str]:
    """The ``|modifier`` names in an "unknown pipe element" message that this engine lacks.

    The message ends with the selection key that carried them, e.g.
    ``... key:detection -> selection -> Image|fictional``.
    """
    if "unknown pipe element" not in line:
        return []
    _, _, key = line.partition("key:")
    field = key.split("->")[-1].strip()
    return [part for part in field.split("|")[1:] if part and part not in _KNOWN_PIPES]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_rules")
    ap.add_argument("--rules", required=True, help="the candidate rule directory")
    ap.add_argument("--config", required=True, help="the Hayabusa config directory")
    ap.add_argument("--compare-to", default="", help="the live rule directory, to catch a sudden drop")
    ap.add_argument("--sample", default="", help="a JSONL record file that must still produce detections")
    ap.add_argument("--min-detections", type=int, default=1)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    problems: list[str] = []
    notes: list[str] = []

    candidate = inspect(Path(args.rules), Path(args.config))
    loaded = candidate["loaded"]
    errors = candidate["parse_errors"]
    if loaded == 0:
        problems.append("no rules loaded at all")
    if loaded and errors / max(loaded, 1) > MAX_PARSE_ERROR_RATE:
        problems.append(f"{errors} of {loaded} rules failed to parse (over {MAX_PARSE_ERROR_RATE:.0%})")
    if candidate["unsupported_modifiers"]:
        notes.append(
            "rules use modifiers this engine does not implement: "
            + ", ".join(f"{name} x{count}" for name, count in candidate["unsupported_modifiers"].items())
        )

    live_loaded = None
    if args.compare_to and Path(args.compare_to).is_dir():
        live = inspect(Path(args.compare_to), Path(args.config))
        live_loaded = live["loaded"]
        if live_loaded and loaded < live_loaded * (1 - MAX_SHRINK):
            problems.append(
                f"the candidate loads {loaded} rules against the live set's {live_loaded} "
                f"-- more than a {MAX_SHRINK:.0%} drop"
            )
        else:
            notes.append(f"rule count {live_loaded} -> {loaded}")

    detections = None
    if args.sample:
        sample = Path(args.sample)
        if not sample.is_file():
            problems.append(f"the sample {sample} does not exist")
        else:
            detector = Detector(candidate["rule_set"], candidate["config"])
            found = list(detector.scan_records(sample.name, iter_jsonl_records(sample)))
            found.extend(detector.finish())
            detections = len(found)
            if detections < args.min_detections:
                problems.append(
                    f"the sample produced {detections} detections, fewer than the {args.min_detections} expected"
                )
            else:
                notes.append(f"the sample still produces {detections} detections")

    report = {
        "ok": not problems,
        "loaded": loaded,
        "parse_errors": errors,
        "live_loaded": live_loaded,
        "sample_detections": detections,
        "unsupported_modifiers": candidate["unsupported_modifiers"],
        "problems": problems,
        "notes": notes,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"rules loaded : {loaded:,}")
        print(f"parse errors : {errors:,}")
        for note in notes:
            print(f"note         : {note}")
        for problem in problems:
            print(f"PROBLEM      : {problem}", file=sys.stderr)
        print("PASS" if report["ok"] else "FAIL")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
