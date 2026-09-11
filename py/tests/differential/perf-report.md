# hayabusa-py throughput

Two measurements on the same 2-vCPU container, both against Hayabusa 4.0.0 where a baseline was
taken. Reproduce either with `tests/differential/perf.py`; the numbers are only meaningful
relative to a Hayabusa run on the *same* host.

## The mixed sample corpus

Every file of `hayabusa-sample-evtx`: a realistic blend of channels, and the set the fidelity
numbers come from.

- host: Linux-6.18.44-fc-v24-x86_64-with-glibc2.39, python 3.14.7
- corpus: 599 files, 47,699 events

| run | rule load (s) | scan (s) | events/s | detections | peak RSS (MB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| python, 1 worker | 5.4 | 129.5 | 368 | 32,447 | 529 |
| python, 2 workers | 5.2 | 92.2 | 517 | 32,447 | 529 |
| hayabusa (rust, all cores) | - | 45.8 | 1,041 | 32,447 | - |

Python is 2.8x Hayabusa's wall clock on this host.

## A Security-only load, at upload scale

The same security log repeated to 198,345 events, split into eight parts the way the reader's
record-range splitter divides one large file on Windows. Security events are the demanding case:
far more rules target them, so the per-event cost is roughly twice the corpus average.

- host: Linux-6.18.44-fc-v24-x86_64-with-glibc2.39, python 3.14.7
- corpus: 8 files, 198,345 events

| run | rule load (s) | scan (s) | events/s | detections | peak RSS (MB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| python, 1 worker | 5.8 | 1190.9 | 167 | 144,720 | 1639 |
| python, 2 workers | 5.3 | 719.2 | 276 | 144,720 | 1639 |

Both runs produced the same 144,720 detections, which is the parallel scan agreeing with the
single-process one at scale.

## What this says about the 500 MB threshold

A 500 MB `Security.evtx` holds roughly 600,000-800,000 events. At the measured 167 events/s per
core that is about 70 core-minutes of work, and the second worker here returned 1.65x rather than
2x, so landing inside ten minutes needs on the order of nine or ten cores rather than seven. That
is an extrapolation from a two-core container: measure it on the real server with a real file
before treating it as a decision.

## Memory

Peak RSS reached 1.6 GB for 144,720 detections, about 11 KB per rendered row. The scan holds
every rendered row in memory until the timeline is sorted, so memory tracks the number of
*detections*, not the size of the log. This corpus is deliberately detection-dense (73% of its
events match at least one rule, mostly informational); a typical Security log is far less dense.
If a real workload does turn out to be both large and dense, the fix is to have each worker write
its own sorted timeline and merge them on disk, which trades a little wall clock for flat memory.
