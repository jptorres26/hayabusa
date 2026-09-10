"""Condition expression compiler (port of ``src/detections/rule/condition_parser.rs``).

Grammar accepted by Hayabusa: selection names, ``and``/``or``/``not``, parentheses, and the
``all of prefix*`` / ``1 of prefix*`` shorthands (expanded textually before parsing). AND binds
tighter than OR; ``not`` applies to the single operand that follows it. The aggregation part
after a ``|`` is stripped here and handled by :mod:`hayabusa_py.engine.aggregation`.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from hayabusa_py.engine.selection import (
    NarySelectionNode,
    NotSelectionNode,
    RefSelectionNode,
    SelectionNode,
)

_TOKEN_PATTERNS = [re.compile(r"^\("), re.compile(r"^\)"), re.compile(r"^ "), re.compile(r"^[\w+]+")]
_RE_PIPE = re.compile(r"\|.*")
_OF_SELECTION = re.compile(r"(all|1) of ([^*]+)\*")


class ConditionParseError(ValueError):
    pass


# Token representation: plain strings for the lexer tokens, dataclasses for the pseudo tokens.
LEFT, RIGHT, SPACE, NOT, AND, OR = "(", ")", " ", "not", "and", "or"


@dataclass(slots=True)
class Ref:
    name: str


@dataclass(slots=True)
class Paren:
    inner: Any


@dataclass(slots=True)
class AndGroup:
    items: list[Any]


@dataclass(slots=True)
class OrGroup:
    items: list[Any]


@dataclass(slots=True)
class NotGroup:
    inner: Any


def _to_token(text: str) -> Any:
    if text in (LEFT, RIGHT, SPACE, NOT, AND, OR):
        return text
    return Ref(text)


def convert_condition(condition: str, node_keys: Sequence[str]) -> str:
    """Expand ``all of selection*`` / ``1 of selection*`` into explicit and/or expressions."""
    converted = condition
    for match in _OF_SELECTION.finditer(condition):
        text = match.group(0)
        sep = " and " if text.startswith("all") else " or "
        prefix = text.replace("*", "").replace("all of ", "").replace("1 of ", "")
        replaced = sep.join(key for key in node_keys if key.startswith(prefix))
        converted = converted.replace(text, f"({replaced})")
    return converted


def tokenize(condition: str) -> list[Any]:
    tokens: list[Any] = []
    rest = condition
    while rest:
        for pattern in _TOKEN_PATTERNS:
            match = pattern.match(rest)
            if match:
                break
        else:
            raise ConditionParseError("An unusable character was found.")
        text = match.group(0)
        rest = rest[len(text) :]
        token = _to_token(text)
        if token == SPACE and not isinstance(token, Ref):
            continue
        tokens.append(token)
    return tokens


def _parse_parenthesis(tokens: list[Any]) -> list[Any]:
    result: list[Any] = []
    iterator = iter(tokens)
    for token in iterator:
        if token != LEFT or isinstance(token, Ref):
            result.append(token)
            continue
        left_cnt, right_cnt = 1, 0
        sub_tokens: list[Any] = []
        for inner in iterator:
            if inner == LEFT and not isinstance(inner, Ref):
                left_cnt += 1
            elif inner == RIGHT and not isinstance(inner, Ref):
                right_cnt += 1
            if left_cnt == right_cnt:
                break
            sub_tokens.append(inner)
        if left_cnt != right_cnt:
            raise ConditionParseError("')' was expected but not found.")
        result.append(Paren(_parse(sub_tokens)))
    if any(token == RIGHT and not isinstance(token, Ref) for token in result):
        raise ConditionParseError("'(' was expected but not found.")
    return result


def _parse_operand_container(sub_tokens: list[Any]) -> Any:
    if len(sub_tokens) >= 3:
        raise ConditionParseError("Unknown error. Maybe it is because there are multiple names of selection nodes.")
    if not sub_tokens:
        raise ConditionParseError("Unknown error.")
    if len(sub_tokens) == 1:
        token = sub_tokens[0]
        if token == NOT and not isinstance(token, Ref):
            raise ConditionParseError("An illegal not was found.")
        return token
    first, second = sub_tokens
    if first == NOT and not isinstance(first, Ref):
        if second == NOT and not isinstance(second, Ref):
            raise ConditionParseError("Not is continuous.")
        return NotGroup(second)
    raise ConditionParseError("Unknown error. Maybe it is because there are multiple names of selection nodes.")


def _is_op(token: Any) -> bool:
    return not isinstance(token, (Ref, Paren, AndGroup, OrGroup, NotGroup)) and token in (AND, OR)


def _to_operand_container(tokens: list[Any]) -> list[Any]:
    result: list[Any] = []
    grouped: list[Any] = []
    for token in tokens:
        if _is_op(token):
            if not grouped:
                result.append(token)
                continue
            result.append(_parse_operand_container(grouped))
            result.append(token)
            grouped = []
            continue
        grouped.append(token)
    if grouped:
        result.append(_parse_operand_container(grouped))
    return result


def _parse_and_or_operator(tokens: list[Any]) -> Any:
    if not tokens:
        raise ConditionParseError("Unknown error.")
    tokens = _to_operand_container(tokens)
    if _is_op(tokens[0]) or _is_op(tokens[-1]):
        raise ConditionParseError("An illegal logical operator(and, or) was found.")
    operands: list[Any] = []
    operators: list[Any] = []
    for index, token in enumerate(tokens):
        if (index % 2 == 1) != _is_op(token):
            raise ConditionParseError("The use of a logical operator(and, or) was wrong.")
        (operators if index % 2 else operands).append(token)
    operand_iter = iter(operands)
    groups: list[Any] = []
    and_group: list[Any] = []
    operators.append(OR)  # sentinel to flush the final AND run
    for operator in operators:
        if operator == OR:
            if not and_group:
                groups.append(next(operand_iter))
            else:
                and_group.append(next(operand_iter))
                groups.append(AndGroup(and_group))
            and_group = []
        else:
            and_group.append(next(operand_iter))
    if len(groups) == 1:
        return groups[0]
    return OrGroup(groups)


def _parse(tokens: list[Any]) -> Any:
    return _parse_and_or_operator(_parse_parenthesis(tokens))


def _into_selection_node(token: Any, name_to_node: dict[str, SelectionNode]) -> SelectionNode:
    if isinstance(token, Ref):
        node = name_to_node.get(token.name)
        if node is None:
            raise ConditionParseError(f"{token.name} is not defined.")
        return RefSelectionNode(node)
    if isinstance(token, Paren):
        return _into_selection_node(token.inner, name_to_node)
    if isinstance(token, AndGroup):
        return NarySelectionNode(True, [_into_selection_node(item, name_to_node) for item in token.items])
    if isinstance(token, OrGroup):
        return NarySelectionNode(False, [_into_selection_node(item, name_to_node) for item in token.items])
    if isinstance(token, NotGroup):
        return NotSelectionNode(_into_selection_node(token.inner, name_to_node))
    raise ConditionParseError("Unknown error")


def compile_condition(condition: str, name_to_node: dict[str, SelectionNode]) -> SelectionNode:
    """``ConditionCompiler::compile_condition``. Raises ConditionParseError with Hayabusa's text."""
    converted = convert_condition(condition, list(name_to_node.keys()))
    match = _RE_PIPE.search(converted)
    if match:
        converted = converted.replace(match.group(0), "")
    try:
        tokens = tokenize(converted)
        parsed = _parse(tokens)
        return _into_selection_node(parsed, name_to_node)
    except ConditionParseError as error:
        raise ConditionParseError(f"A condition parse error has occurred. {error}") from None
