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

The first Security-scale run peaked at 1.6 GB of RSS for 144,720 detections, about 11 KB per
rendered row, because every row was held until the timeline could be sorted. Memory tracked the
number of *detections* rather than the size of the log — fine for a corpus scan, not fine for a
service whose upload cap allows logs that could produce far more.

Rows are now written out in sorted runs as they are rendered (20,000 at a time) and merged when
the results are written, so memory is bounded by the flush interval instead. The same load now
peaks at **941 MB**, and finished slightly faster (1,405 s against 1,537 s) since less is being
kept alive for the garbage collector to walk:

| version | peak RSS | wall | detections |
| --- | ---: | ---: | ---: |
| rows held until sorted | 1,639 MB | 1,537 s | 144,720 |
| spooled per finished job | 1,274 MB | — | 144,720 |
| spooled as rendered (current) | 941 MB | 1,405 s | 144,720 |

What remains is largely the fixed cost of the rule set: the mixed-corpus scan, with a fraction of
the detections, peaks at 529 MB. So memory now scales with the rules loaded, which is constant,
rather than with what is found in the log. The spooled output is byte-identical to sorting in
memory — verified on a 9,648-row timeline, same rows in the same order.
