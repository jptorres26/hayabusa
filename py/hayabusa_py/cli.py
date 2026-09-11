"""``hayabusa-py`` command line: a ``dfir-timeline`` compatible subset of Hayabusa's CLI.

    hayabusa-py dfir-timeline -d <dir> | -f <file> [-o out] [-t csv|json|jsonl] [-p profile]
                              [-U] [-O] [-m level] [-A] [-a] [-J] [--evtx-jsonl]
                              [-r rules] [-c rules-config] [--config config]

Input on Windows is ``.evtx`` (read through the Windows Event Log API); everywhere, ``-J`` reads
``.json``/``.jsonl`` exports and ``--evtx-jsonl`` reads ``evtx_dump`` fixtures.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from hayabusa_py.engine.detect import Detection, Detector, RuleSet, load_rule_set
from hayabusa_py.engine.parallel import (
    WorkerSetup,
    merge_countdata,
    scan_jobs,
    split_jobs,
    worker_count,
)
from hayabusa_py.engine.timeutil import TimeFormatOptions
from hayabusa_py.evtx.errors import EvtxReadError
from hayabusa_py.evtx.jsonl_reader import (
    iter_fixture_records,
    iter_json_records,
    normalize_json_input,
)
from hayabusa_py.output.config import OutputConfig
from hayabusa_py.output.render import DetectInfo, render
from hayabusa_py.output.writers import (
    duplicate_indices,
    sort_key,
    write_csv,
    write_json,
    write_jsonl,
)
from hayabusa_py.rules.config import RulesConfig
from hayabusa_py.rules.loader import LEVELS, RuleFilterOptions

LEVEL_ORDER = ["emergency", "critical", "high", "medium", "low", "informational"]


def _default_paths() -> tuple[Path, Path, Path]:
    """rules/, rules/config and config/ next to the package (or the current directory)."""
    for base in (Path.cwd(), Path(__file__).resolve().parent.parent):
        if (base / "rules").is_dir() and (base / "config").is_dir():
            return base / "rules", base / "rules" / "config", base / "config"
    return Path("rules"), Path("rules") / "config", Path("config")


def collect_files(paths: list[Path], extensions: set[str]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
            continue
        if not path.is_dir():
            print(f"[ERROR] fail to read metadata of file: {path}", file=sys.stderr)
            continue
        for entry in sorted(path.rglob("*")):
            if entry.is_file() and entry.suffix.lstrip(".").lower() in extensions:
                files.append(entry)
    return files


def make_reader(args: argparse.Namespace, log: Callable[[str], None] = lambda _line: None) -> tuple[Callable[[Path], Iterator[Any]], set[str]]:
    if args.evtx_jsonl:
        return iter_fixture_records, {"jsonl"}
    if args.json_input:
        def read_json(path: Path) -> Iterator[Any]:
            for record in iter_json_records(path):
                yield normalize_json_input(record)

        return read_json, {"json", "jsonl"}
    if sys.platform == "win32":
        from hayabusa_py.evtx.wevtapi_reader import iter_evtx_records

        def read_evtx(path: Path) -> Iterator[Any]:
            # Per-record render failures go to the error log; the rest of the file is still read.
            return iter_evtx_records(path, on_error=log)

        return read_evtx, {"evtx"} | set(args.target_file_ext or [])
    raise SystemExit("[ERROR] Reading .evtx files needs the Windows Event Log API; on this platform use -J (JSON input) or --evtx-jsonl.")


def reader_kind(args: argparse.Namespace) -> str:
    """Which reader the worker processes should build (see ``parallel.WorkerSetup``)."""
    if args.evtx_jsonl:
        return "fixture"
    if args.json_input:
        return "json"
    return "evtx"


def _record_counter() -> Callable[[str], int] | None:
    """``record_count`` when the Windows reader is available, else None (no range splitting)."""
    if sys.platform != "win32":
        return None
    from hayabusa_py.evtx.wevtapi_reader import record_count

    return record_count


def peek_channel(reader: Callable[[Path], Iterator[Any]], path: Path) -> str | None:
    """``filter::peek_channel_from_evtx_first_record`` for one file."""
    try:
        first = next(iter(reader(path)), None)
    except Exception:
        return None
    if first is None:
        return None
    try:
        channel = first["Event"]["System"]["Channel"]
    except (KeyError, TypeError):
        return ""
    return channel if isinstance(channel, str) else ""


def rule_channels(rule_yaml: Any) -> list[str]:
    """Every ``Channel:`` string value anywhere in the rule (``filter::extract_channel_from_rules``)."""
    found: list[str] = []

    def visit(key: str, value: Any) -> None:
        if isinstance(value, str) and key == "Channel":
            found.append(value)
        elif isinstance(value, dict):
            for k, v in value.items():
                visit(str(k), v)
        elif isinstance(value, list):
            for item in value:
                visit(key, item)

    visit("", rule_yaml)
    return found


def apply_channel_filter(rule_set: RuleSet, files: list[Path], reader: Callable[[Path], Iterator[Any]], *, enable_all_rules: bool, scan_all_files: bool) -> list[Path]:
    """Hayabusa's default channel filter: drop rules no loaded file can trigger and files no
    rule targets (``main.rs`` / ``filter.rs``)."""
    if enable_all_rules and scan_all_files:
        return files
    file_channels = {path: peek_channel(reader, path) for path in files}
    present = {channel for channel in file_channels.values() if channel}
    if not present:
        return files
    matched_channels: set[str] = set()
    keep_rules = []
    for rule in rule_set.rules:
        hit = False
        for value in rule_channels(rule.yaml):
            if "*" in value:
                for channel in present:
                    if value.strip("*") in channel:
                        matched_channels.add(channel)
                        hit = True
            elif value in present:
                matched_channels.add(value)
                hit = True
        if hit or "correlation" in rule.yaml or enable_all_rules:
            keep_rules.append(rule)
    if not enable_all_rules:
        rule_set.rules = keep_rules
    if scan_all_files:
        return files
    return [path for path in files if file_channels.get(path) in matched_channels]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hayabusa-py")
    sub = parser.add_subparsers(dest="command", required=True)
    tl = sub.add_parser("dfir-timeline", help="Create a DFIR timeline (CSV/JSON/JSONL)")
    src = tl.add_mutually_exclusive_group(required=True)
    src.add_argument("-d", "--directory", type=Path, help="Directory of multiple .evtx files")
    src.add_argument("-f", "--file", type=Path, help="File path to one .evtx file")
    tl.add_argument("-o", "--output", type=Path, help="Save the timeline to a file (default: stdout)")
    tl.add_argument("-t", "--output-type", default="csv", choices=["csv", "json", "jsonl"], type=str.lower)
    tl.add_argument("-p", "--profile", default=None, help="Output profile (config/profiles.yaml)")
    tl.add_argument("-C", "--clobber", action="store_true", help="Overwrite the output file")
    tl.add_argument("-J", "--json-input", action="store_true", help="Scan JSON formatted logs (.json/.jsonl)")
    tl.add_argument("--evtx-jsonl", action="store_true", help="Scan evtx_dump JSONL dumps (development)")
    tl.add_argument("--target-file-ext", nargs="*", help="Additional evtx file extensions")
    tl.add_argument("-r", "--rules", type=Path, help="Rule directory or file (default: ./rules)")
    tl.add_argument("-c", "--rules-config", type=Path, help="Rule config directory (default: ./rules/config)")
    tl.add_argument("--config", type=Path, help="Hayabusa config directory (default: ./config)")
    tl.add_argument("-m", "--min-level", default="informational", choices=LEVELS)
    tl.add_argument("-e", "--exact-level", default="", choices=[""] + LEVELS)
    tl.add_argument("-A", "--enable-all-rules", action="store_true")
    tl.add_argument("-a", "--scan-all-evtx-files", action="store_true")
    tl.add_argument("-D", "--enable-deprecated-rules", action="store_true")
    tl.add_argument("-u", "--enable-unsupported-rules", action="store_true")
    tl.add_argument("-n", "--enable-noisy-rules", action="store_true")
    tl.add_argument("--include-status", nargs="*")
    tl.add_argument("--exclude-status", nargs="*")
    tl.add_argument("--include-tag", nargs="*")
    tl.add_argument("--exclude-tag", nargs="*")
    tl.add_argument("-X", "--remove-duplicate-detections", action="store_true")
    tl.add_argument("-U", "--utc", action="store_true")
    tl.add_argument("-O", "--iso-8601", action="store_true")
    tl.add_argument("--rfc-2822", action="store_true")
    tl.add_argument("--rfc-3339", action="store_true")
    tl.add_argument("--us-time", action="store_true")
    tl.add_argument("--us-military-time", action="store_true")
    tl.add_argument("--european-time", action="store_true")
    tl.add_argument("-b", "--disable-abbreviations", action="store_true")
    tl.add_argument("-F", "--no-field-data-mapping", action="store_true")
    tl.add_argument("--no-pwsh-field-extraction", action="store_true")
    tl.add_argument("--no-index", action="store_true", help="Evaluate every rule on every event (slower; for verification)")
    tl.add_argument("-w", "--workers", type=int, default=1, help="Scan with this many processes (0 = one per core, 1 = in-process)")
    tl.add_argument("--split-over", type=int, default=200_000, help="Split a file with more than this many records into record ranges (0 disables)")
    tl.add_argument("-q", "--quiet", action="store_true")
    tl.add_argument("-N", "--no-summary", action="store_true")
    args = parser.parse_args(argv)

    default_rules, default_rules_config, default_config = _default_paths()
    rules_path = args.rules or default_rules
    rules_config = args.rules_config or (rules_path / "config" if rules_path.is_dir() else default_rules_config)
    config_dir = args.config or default_config
    if args.output is not None and args.output.exists() and not args.clobber:
        print(f"[ERROR] The file {args.output} already exists. Please specify a different filename or add the -C, --clobber option to overwrite the file.", file=sys.stderr)
        return 1

    log_lines: list[str] = []
    started = time.perf_counter()
    if not args.quiet:
        print(f"Start time: {time.strftime('%Y/%m/%d %H:%M')}")

    reader, extensions = make_reader(args, log_lines.append)
    files = collect_files([args.directory or args.file], extensions)
    if not args.quiet:
        print(f"Total event log files: {len(files)}")
    if not files:
        print("[ERROR] No .evtx files were found.", file=sys.stderr)
        return 1

    config = RulesConfig.load(rules_config, config_dir / "expand")
    options = RuleFilterOptions(
        min_level=args.min_level,
        exact_level=args.exact_level,
        include_status=set(args.include_status) if args.include_status else {"*"},
        exclude_status=set(args.exclude_status or []),
        enable_deprecated_rules=args.enable_deprecated_rules,
        enable_unsupported_rules=args.enable_unsupported_rules,
        enable_noisy_rules=args.enable_noisy_rules,
        include_tag=args.include_tag,
        exclude_tag=args.exclude_tag,
    )
    if not args.quiet:
        print("Loading detection rules. Please wait.")
    rule_set = load_rule_set(rules_path, config, options, log_lines.append)
    if not args.quiet:
        loaded = rule_set.loaded
        print(f"Excluded rules: {loaded.rule_load_cnt.get('excluded', 0):,}")
        print(f"Noisy rules: {loaded.rule_load_cnt.get('noisy', 0):,} ({'Enabled' if args.enable_noisy_rules else 'Disabled'})")
        for status in ("deprecated", "experimental", "stable", "test", "unsupported"):
            count = loaded.rule_status_cnt.get(status, 0)
            if count:
                print(f"{status.capitalize()} rules: {count:,}")
        print(f"Hayabusa rules: {loaded.rule_type_cnt.get('Hayabusa', 0):,}")
        print(f"Sigma rules: {loaded.rule_type_cnt.get('Sigma', 0):,}")
        print(f"Total detection rules: {len(rule_set.rules):,}")
        if rule_set.parse_error_count:
            print(f"Rule parse errors: {rule_set.parse_error_count:,}")
    if not rule_set.rules:
        print("[ERROR] No rules were loaded. Please download the latest rules with the update-rules command.", file=sys.stderr)
        return 1

    if not args.json_input:
        files = apply_channel_filter(rule_set, files, reader, enable_all_rules=args.enable_all_rules, scan_all_files=args.scan_all_evtx_files)
        if not args.quiet and not (args.enable_all_rules and args.scan_all_evtx_files):
            print(f"Evtx files loaded after channel filter: {len(files):,}")
            print(f"Detection rules enabled after channel filter: {len(rule_set.rules):,}")

    time_format = TimeFormatOptions(
        utc=args.utc,
        iso_8601=args.iso_8601,
        rfc_2822=args.rfc_2822,
        rfc_3339=args.rfc_3339,
        us_time=args.us_time,
        us_military_time=args.us_military_time,
        european_time=args.european_time,
    )
    fmt = args.output_type
    try:
        out_cfg = OutputConfig.load(
            config_dir,
            rules_config,
            args.profile,
            time_format=time_format,
            json_timeline=fmt != "csv",
            disable_abbreviation=args.disable_abbreviations,
            no_field_data_mapping=args.no_field_data_mapping,
            output_to_file=args.output is not None,
        )
    except ValueError as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1
    out_cfg.json_input = args.json_input
    if not args.quiet:
        print(f"Output profile: {args.profile or 'default'}")
        print("Scanning in progress. Please wait.")

    detector = Detector(rule_set, config, use_index=not args.no_index, json_input_flag=args.json_input, log=log_lines.append)
    workers = worker_count(args.workers) if args.workers != 1 else 1
    infos: list[DetectInfo] = []
    if workers > 1:
        setup = WorkerSetup(
            rules_path=str(rules_path),
            rules_config_dir=str(rules_config),
            config_dir=str(config_dir),
            expand_dir=str(config_dir / "expand"),
            filter_options=options,
            profile=args.profile,
            time_format=time_format,
            json_timeline=fmt != "csv",
            reader=reader_kind(args),
            json_input_flag=args.json_input,
            use_index=not args.no_index,
            disable_abbreviation=args.disable_abbreviations,
            no_field_data_mapping=args.no_field_data_mapping,
            output_to_file=args.output is not None,
            keep_rule_paths=frozenset(rule.rule_path for rule in rule_set.rules),
        )
        jobs = split_jobs(
            [(str(path), str(path)) for path in files],
            workers=workers,
            split_over=args.split_over if setup.reader == "evtx" else 0,
            count_records=_record_counter() if setup.reader == "evtx" else None,
        )
        if not args.quiet:
            print(f"Scanning with {workers} processes ({len(jobs)} jobs).")
        fragments = []
        for result in scan_jobs(jobs, setup, workers=workers):
            infos.extend(result.rows)
            fragments.append(result.countdata)
            log_lines.extend(result.log_lines)
            detector.stats.merge(result.stats)
            if result.error:
                log_lines.append(f"[ERROR] {result.error}")
                print(f"[ERROR] {result.error}", file=sys.stderr)
        merge_countdata(rule_set.rules, fragments)
        infos.extend(render(det, out_cfg, config.eventkey_alias) for det in detector.finish())
    else:
        detections: list[Detection] = []
        for path in files:
            try:
                detections.extend(detector.scan_records(str(path), reader(path)))
            except EvtxReadError as exc:
                # One unreadable file must not lose the rest of the upload (Hayabusa logs and moves on).
                log_lines.append(f"[ERROR] {exc}")
                print(f"[ERROR] {exc}", file=sys.stderr)
        detections.extend(detector.finish())
        infos = [render(det, out_cfg, config.eventkey_alias) for det in detections]
    infos.sort(key=sort_key)
    if args.remove_duplicate_detections:
        skip = duplicate_indices(infos)
        infos = [info for index, info in enumerate(infos) if index not in skip]

    handle = open(args.output, "w", encoding="utf-8", newline="") if args.output is not None else sys.stdout
    try:
        if fmt == "jsonl":
            write_jsonl(handle, infos)
        elif fmt == "json":
            write_json(handle, infos)
        else:
            write_csv(handle, infos)
        if args.output is None:
            handle.write("\n")
    finally:
        if args.output is not None:
            handle.close()

    if not args.no_summary and not args.quiet:
        stats = detector.stats
        counts = Counter(LEVEL_ORDER[6 - info.level] if 1 <= info.level <= 6 else "undefined" for info in infos)
        unique = Counter()
        for info in infos:
            unique[(info.level, info.ruleid)] += 1
        print()
        print("Results Summary:")
        print(f"Events with hits / Total events: {stats.events_with_hits:,} / {stats.events:,}")
        print(f"Total | Unique detections: {len(infos):,} | {len(unique):,}")
        for level_name in LEVEL_ORDER:
            level_num = 6 - LEVEL_ORDER.index(level_name)
            uniq = sum(1 for (lvl, _) in unique if lvl == level_num)
            print(f"Total | Unique {level_name} detections: {counts.get(level_name, 0):,} | {uniq:,}")
        print(f"Elapsed time: {time.perf_counter() - started:.1f}s")
        if args.output is not None:
            print(f"Saved file: {args.output}")
    if log_lines:
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        log_path = logs_dir / f"errorlog-{time.strftime('%Y%m%d_%H%M%S')}.log"
        log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"Errors were generated. Please check {log_path} for details.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
