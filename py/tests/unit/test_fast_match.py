"""Port of the ``mod tests`` of ``src/detections/rule/fast_match.rs`` (lines 178-246)."""

from __future__ import annotations

from hayabusa_py.engine.matchers import (
    FastKind,
    FastMatch,
    convert_to_fast_match,
    ends_with_ignore_case,
    eq_ignore_case,
    starts_with_ignore_case,
)


# fast_match.rs:185-191
def test_eq_ignore_case():
    assert eq_ignore_case("abc", "abc")
    assert eq_ignore_case("AbC", "abc")
    assert not eq_ignore_case("abc", "ab")
    assert not eq_ignore_case("ab", "abc")


# fast_match.rs:193-199
def test_starts_with_ignore_case():
    assert starts_with_ignore_case("abc", "ab")
    assert starts_with_ignore_case("AbC", "ab")
    assert starts_with_ignore_case("abc", "abcd") is False
    assert starts_with_ignore_case("aab", "ab") is False


# fast_match.rs:201-207
def test_ends_with_ignore_case():
    assert ends_with_ignore_case("abc", "bc")
    assert ends_with_ignore_case("AbC", "bc")
    assert ends_with_ignore_case("bc", "bcd") is False
    assert ends_with_ignore_case("bcd", "abc") is False


# fast_match.rs:209-245
def test_convert_to_fast_match():
    assert convert_to_fast_match("ab?", True) is None
    assert convert_to_fast_match("a*c", True) is None
    assert convert_to_fast_match("*a*b", True) is None
    assert convert_to_fast_match("*a*b*", True) is None
    assert convert_to_fast_match(r"a\*", True) is None
    assert convert_to_fast_match(r"a\\\*", True) is None
    assert convert_to_fast_match("abc*", True) == [FastMatch(FastKind.STARTS_WITH, "abc")]
    assert convert_to_fast_match(r"abc\\*", True) == [FastMatch(FastKind.STARTS_WITH, "abc\\")]
    assert convert_to_fast_match("*abc", True) == [FastMatch(FastKind.ENDS_WITH, "abc")]
    assert convert_to_fast_match("*abc*", True) == [FastMatch(FastKind.CONTAINS, "abc")]
    assert convert_to_fast_match("abc", True) == [FastMatch(FastKind.EXACT, "abc")]
    assert convert_to_fast_match("あいう", True) == [FastMatch(FastKind.EXACT, "あいう")]
    assert convert_to_fast_match(r"\\\\127.0.0.1\\", True) == [
        FastMatch(FastKind.EXACT, "\\\\127.0.0.1\\")
    ]
