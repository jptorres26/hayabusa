"""hayabusa-py: a Python re-creation of Hayabusa's Windows event log detection engine.

The package mirrors the layout of the Rust implementation it was ported from
(https://github.com/Yamato-Security/hayabusa):

- ``evtx``   – record model and EVTX readers (Windows Event Log API, JSON/JSONL input)
- ``rules``  – rule file discovery/filtering (``src/yaml.rs``) and rules/config files
- ``engine`` – selection/condition/matcher semantics (``src/detections/rule/``)
- ``output`` – profiles, details rendering and timeline writers (``src/results/``)
"""

__version__ = "0.1.0"
