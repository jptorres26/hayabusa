# A minimal Hayabusa `config/` for tests

Enough of Hayabusa 4.0.0's `config/` for the output layer to load without the full release: the
default profile, the named profiles, the MITRE tactic names and the (empty) critical-systems
list, plus an empty `expand/` directory. Copied from the release, so it carries Hayabusa's
licence and attribution like the rest of `tests/golden/`.

Tests that need the real thing — the differential harness, the performance harness — take a
`--config-dir` pointing at an actual Hayabusa release instead.
