"""Port of the ``mod tests`` of ``src/detections/rule/base64_match.rs`` (lines 155-328)."""

from __future__ import annotations

from hayabusa_py.engine.matchers import (
    FastKind,
    FastMatch,
    Pipe,
    _base64_offset,
    convert_to_base64_str,
    to_base64_utf8,
    to_base64_utf16be,
    to_base64_utf16le_with_bom,
)


def contains(text: str) -> FastMatch:
    return FastMatch(FastKind.CONTAINS, text)


# base64_match.rs:159-175
def test_base64_offset():
    # Rust passes the string twice (raw and NUL-filtered); the Python port takes it once.
    b64_str = "aGVsbG8gd29ybGQ="
    assert _base64_offset(0, b64_str) == "aGVsbG8gd29ybG"
    assert _base64_offset(1, b64_str) == "VsbG8gd29ybG"
    assert _base64_offset(2, b64_str) == "sbG8gd29ybG"


# base64_match.rs:177-194
def test_convert_to_base64_str_utf8():
    val = "Hello, world!"
    matches = convert_to_base64_str(None, val)
    assert matches is not None
    assert matches[0] == contains("SGVsbG8sIHdvcmxkI")
    assert matches[1] == contains("hlbGxvLCB3b3JsZC")
    assert matches[2] == contains("IZWxsbywgd29ybGQh")


# base64_match.rs:196-213
def test_convert_to_base64_str_wide():
    val = "Hello, world!"
    matches = convert_to_base64_str(Pipe.WIDE, val)
    assert matches is not None
    assert matches[0] == contains("SABlAGwAbABvACwAIAB3AG8AcgBsAGQAIQ")
    assert matches[1] == contains("gAZQBsAGwAbwAsACAAdwBvAHIAbABkACEA")
    assert matches[2] == contains("IAGUAbABsAG8ALAAgAHcAbwByAGwAZAAhA")


# base64_match.rs:214-232
def test_convert_to_base64_str_utf16le():
    val = "Hello, world!"
    matches = convert_to_base64_str(Pipe.UTF16LE, val)
    assert matches is not None
    assert matches[0] == contains("SABlAGwAbABvACwAIAB3AG8AcgBsAGQAIQ")
    assert matches[1] == contains("gAZQBsAGwAbwAsACAAdwBvAHIAbABkACEA")
    assert matches[2] == contains("IAGUAbABsAG8ALAAgAHcAbwByAGwAZAAhA")


# base64_match.rs:234-252
def test_convert_to_base64_str_utf16be():
    val = "Hello, world!"
    matches = convert_to_base64_str(Pipe.UTF16BE, val)
    assert matches is not None
    assert matches[0] == contains("AEgAZQBsAGwAbwAsACAAdwBvAHIAbABkAC")
    assert matches[1] == contains("BIAGUAbABsAG8ALAAgAHcAbwByAGwAZAAh")
    assert matches[2] == contains("ASABlAGwAbABvACwAIAB3AG8AcgBsAGQAI")


# base64_match.rs:254-260
def test_to_base64_utf16be():
    assert to_base64_utf16be("A") == "AEE"
    assert to_base64_utf16be("Hello") == "AEgAZQBsAGwAbw"
    assert to_base64_utf16be("こんにちは") == "MFMwkzBrMGEwbw"
    assert to_base64_utf16be("") == ""


# base64_match.rs:262-286
def test_to_base64_utf16le_with_bom():
    # Without a BOM (same result as the pre-existing function)
    assert to_base64_utf16le_with_bom("A", False) == "QQA"
    assert to_base64_utf16le_with_bom("Hello", False) == "SABlAGwAbABvAA"
    assert to_base64_utf16le_with_bom("", False) == ""

    # With a BOM (0xFF 0xFE is prepended)
    assert to_base64_utf16le_with_bom("A", True) == "//5BAA"
    assert to_base64_utf16le_with_bom("Hello", True) == "//5IAGUAbABsAG8A"
    assert to_base64_utf16le_with_bom("", True) == "//4"

    # Test with Japanese strings
    assert to_base64_utf16le_with_bom("こんにちは", False) == "UzCTMGswYTBvMA"
    assert to_base64_utf16le_with_bom("こんにちは", True) == "//5TMJMwazBhMG8w"


# base64_match.rs:288-301
def test_utf16_comparison():
    input_str = "テスト"
    utf16le = to_base64_utf16le_with_bom(input_str, False)
    utf16be = to_base64_utf16be(input_str)

    # Verify that UTF-16LE and UTF-16BE produce different results
    assert utf16le != utf16be

    # Verify that UTF-8 and UTF-16 also produce different results
    utf8 = to_base64_utf8(input_str)
    assert utf8 != utf16le
    assert utf8 != utf16be


# base64_match.rs:303-327
def test_to_base64_utf8():
    # Basic English strings
    assert to_base64_utf8("Hello") == "SGVsbG8"
    assert to_base64_utf8("A") == "QQ"
    assert to_base64_utf8("Hello, World!") == "SGVsbG8sIFdvcmxkIQ"

    # Empty string
    assert to_base64_utf8("") == ""

    # Japanese strings
    assert to_base64_utf8("こんにちは") == "44GT44KT44Gr44Gh44Gv"
    assert to_base64_utf8("テスト") == "44OG44K544OI"

    # Digits and symbols
    assert to_base64_utf8("123") == "MTIz"
    assert to_base64_utf8("!@#$%") == "IUAjJCU"

    # String containing a newline character
    assert to_base64_utf8("line1\nline2") == "bGluZTEKbGluZTI"

    # Special UTF-8 characters
    assert to_base64_utf8("🎉") == "8J+OiQ"
    assert to_base64_utf8("café") == "Y2Fmw6k"
