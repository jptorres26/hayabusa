# hayabusa-py throughput

- host: Linux-6.18.44-fc-v24-x86_64-with-glibc2.39, python 3.14.7
- corpus: 599 files, 47,699 events

| run | rule load (s) | scan (s) | events/s | detections | peak RSS (MB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| python, 1 worker | 5.4 | 129.5 | 368 | 32,447 | 529 |
| python, 2 workers | 5.2 | 92.2 | 517 | 32,447 | 529 |
| hayabusa (rust, all cores) | - | 45.8 | 1,041 | 32,447 | - |

Python is 2.8x Hayabusa's wall clock on this host.
