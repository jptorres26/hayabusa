"""Port of the ``mod tests`` block of ``src/detections/rule/aggregation_parser.rs`` (lines 269-479)."""

from __future__ import annotations

import pytest

from hayabusa_py.engine.aggregation import AggregationParseError, CmpOp, compile_aggregation


def check_aggregation_condition_ope(expr: str, cmp_num: int) -> CmpOp:
    """aggregation_parser.rs:465-478"""
    result = compile_aggregation(expr)
    assert result is not None
    assert result.by_field_name is None
    assert result.field_name is None
    assert result.cmp_num == cmp_num
    return result.cmp_op


def _compile_error(expr: str) -> str:
    with pytest.raises(AggregationParseError) as excinfo:
        compile_aggregation(expr)
    return str(excinfo.value)


# aggregation_parser.rs:275-283
def test_aggregation_condition_compiler_no_count() -> None:
    # Pattern without count.
    result = compile_aggregation("select1 and select2")
    assert result is None


# aggregation_parser.rs:285-307
def test_aggregation_condition_compiler_count_ope() -> None:
    # Normal case: no field inside count, try various operators.
    token = check_aggregation_condition_ope("select1 and select2|count() > 32", 32)
    assert token is CmpOp.GT

    token = check_aggregation_condition_ope("select1 and select2|count() >= 43", 43)
    assert token is CmpOp.GE

    token = check_aggregation_condition_ope("select1 and select2|count() < 59", 59)
    assert token is CmpOp.LT

    token = check_aggregation_condition_ope("select1 and select2|count() <= 12", 12)
    assert token is CmpOp.LE

    token = check_aggregation_condition_ope("select1 and select2|count() == 28", 28)
    assert token is CmpOp.EQ


# aggregation_parser.rs:309-323
def test_aggregation_condition_compiler_count_by() -> None:
    result = compile_aggregation("select1 or select2 | count() by iiibbb > 27")
    assert result is not None
    assert result.by_field_name == "iiibbb"
    assert result.field_name is None
    assert result.cmp_num == 27
    assert result.cmp_op is CmpOp.GT


# aggregation_parser.rs:325-337
def test_aggregation_condition_compiler_count_by_multiple_fields() -> None:
    result = compile_aggregation("select1 or select2 | count() by iiibbb,aaabbb > 27")
    assert result is not None
    assert result.by_field_name == "iiibbb,aaabbb"
    assert result.field_name is None
    assert result.cmp_num == 27
    assert result.cmp_op is CmpOp.GT


# aggregation_parser.rs:339-351
def test_aggregation_condition_compiler_count_by_multiple_fields_with_space() -> None:
    result = compile_aggregation("select1 or select2 | count() by iiibbb, aaabbb > 27")
    assert result is not None
    assert result.by_field_name == "iiibbb, aaabbb"
    assert result.field_name is None
    assert result.cmp_num == 27
    assert result.cmp_op is CmpOp.GT


# aggregation_parser.rs:353-367
def test_aggregation_condition_compiler_count_field() -> None:
    result = compile_aggregation("select1 or select2 | count( hogehoge    ) > 3")
    assert result is not None
    assert result.by_field_name is None
    assert result.field_name == "hogehoge"
    assert result.cmp_num == 3
    assert result.cmp_op is CmpOp.GT


# aggregation_parser.rs:369-383
def test_aggregation_condition_compiler_count_all_field() -> None:
    result = compile_aggregation("select1 or select2 | count( hogehoge) by snsn > 3")
    assert result is not None
    assert result.by_field_name == "snsn"
    assert result.field_name == "hogehoge"
    assert result.cmp_num == 3
    assert result.cmp_op is CmpOp.GT


# aggregation_parser.rs:385-396
def test_aggregation_condition_compiler_only_pipe() -> None:
    assert (
        _compile_error("select1 or select2 |")
        == "An aggregation condition parse error has occurred. There are no strings after the pipe(|)."
    )


# aggregation_parser.rs:398-409
def test_aggregation_condition_compiler_unused_character() -> None:
    assert (
        _compile_error("select1 or select2 | count( hogeess ) by ii-i > 33")
        == "An aggregation condition parse error has occurred. An unusable character was found."
    )


# aggregation_parser.rs:411-419
def test_aggregation_condition_compiler_not_count() -> None:
    # Something other than count is at the beginning.
    assert (
        _compile_error("select1 or select2 | by count( hogehoge) by snsn > 3")
        == "An aggregation condition parse error has occurred. The aggregation condition can only use count."
    )


# aggregation_parser.rs:421-429
def test_aggregation_condition_compiler_no_ope() -> None:
    # Missing comparison operator.
    assert (
        _compile_error("select1 or select2 | count( hogehoge) 3")
        == "An aggregation condition parse error has occurred. The count keyword needs a compare operator and number like '> 3'"
    )


# aggregation_parser.rs:431-439
def test_aggregation_condition_compiler_by() -> None:
    # Nothing after by.
    assert (
        _compile_error("select1 or select2 | count( hogehoge) by")
        == "An aggregation condition parse error has occurred. The by keyword needs a field name like 'by EventID'"
    )


# aggregation_parser.rs:441-449
def test_aggregation_condition_compiler_no_ope_afterby() -> None:
    # No number after the comparison operator.
    assert (
        _compile_error("select1 or select2 | count( hogehoge ) by hoe >")
        == "An aggregation condition parse error has occurred. The compare operator needs a number like '> 3'."
    )


# aggregation_parser.rs:451-463
def test_aggregation_condition_compiler_unnecessary_word() -> None:
    # An extra token after the number.
    assert (
        _compile_error("select1 or select2 | count( hogehoge ) by hoe > 3 33")
        == "An aggregation condition parse error has occurred. An unnecessary word was found."
    )
