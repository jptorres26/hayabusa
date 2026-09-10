# Test oracle: Hayabusa 4.0.0 golden outputs

These files are the reference the Python engine is measured against. They were produced by the
real Hayabusa binary; nothing here is hand-edited.

## Provenance (generated 2026-09-10)

| Item | Value |
| --- | --- |
| Hayabusa release | v4.0.0 "BlackHat Arsenal USA Release", published 2026-08-03 |
| Zip | `hayabusa-4.0.0-lin-x64-musl.zip`, SHA-256 `04d4daf91ad0cc576654e985315f15e412a3ad460f2702f2a9dde3fbd1104a8b` |
| Binary | `hayabusa-4.0.0-lin-x64-musl`, SHA-256 `1b445a4d6ed1d309e3fe1ca75f1884002879f1e3e22c68685135fd51343b263c` |
| Rules | the `rules/` directory bundled in the zip: 4,967 `.yml` files (4,648 load with the default filters: 181 Hayabusa + 4,467 Sigma; 230 deprecated, 42 unsupported, 26 excluded, 12 noisy disabled) |
| Config | the `config/` directory bundled in the zip (profiles.yaml, mitre_tactics.txt, …) and `rules/config/` |
| Corpus | `Yamato-Security/hayabusa-sample-evtx` @ `0845333ecb4afcf64c55c6e10946383f168f308c` (2025-11-06): 599 `.evtx`, 132.8 MiB, 47,699 events |
| Record fixtures | `tests/fixtures/records/sample-evtx/**.evtx.jsonl`, one JSONL per evtx, produced by `evtx_dump` 0.12.2 (`evtx` crate) with `-o jsonl --separate-json-attributes` |
| Machine | Intel Xeon @ 2.10 GHz, 2 vCPUs (cloud container), Linux x86_64 |

The fork's own `test_files/evtx/*.evtx` are zero-byte placeholders in git and cannot be scanned;
the sample corpus is the only evtx oracle.

## Commands

Run from a directory containing a `sample-evtx` symlink to the corpus, with the bundled `rules/`
and `config/` next to the binary (see `.cmd` files for the exact invocations):

```
# mode "all": every rule enabled, every file scanned (no channel filters)
hayabusa dfir-timeline -d sample-evtx -U -w -K -q -C -s -O -A -a -t jsonl -p super-verbose -o all/timeline.super-verbose.jsonl
hayabusa dfir-timeline -d sample-evtx -U -w -K -q -C -s       -A -a -t csv                    -o all/timeline.standard.csv
# mode "default": Hayabusa's channel filter for rules and files
hayabusa dfir-timeline -d sample-evtx -U -w -K -q -C -s -O       -t jsonl -p super-verbose -o default/timeline.super-verbose.jsonl
```

`-O` (ISO-8601) keeps the full evtx timestamp precision; `-s` sorts by time so runs are diffable.
Each run's console output is in the `.log` file and `/usr/bin/time -v` output in the `.time` file.

## Baseline (the yardstick)

| Corpus | Mode | Files scanned | Events | Detections (total / unique) | Wall clock | Max RSS | Events/s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| sample-evtx | all, jsonl super-verbose | 599 | 47,699 | 32,447 / 686 | 44.4 s | 773 MB | ~1,070 |
| sample-evtx | all, csv standard | 599 | 47,699 | 32,447 / 686 | 52.7 s | 816 MB | ~900 |
| sample-evtx | default, jsonl super-verbose | 586 | 46,571 | 32,377 / 684 | 45.2 s | 819 MB | ~1,030 |

Events/s is total events ÷ wall clock and includes loading 4,648 rules (several seconds) and
sorting; on a 2-vCPU container. Use the same machine and flags when comparing the Python engine.
