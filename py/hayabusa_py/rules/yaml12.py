"""YAML loading with the scalar semantics of the Rust ``yaml-rust2`` crate.

Hayabusa parses rules with ``yaml-rust2``, whose plain-scalar interpretation
(``Yaml::from_str``) differs from PyYAML's YAML 1.1 defaults in ways that matter for
detection parity:

* only ``true``/``True``/``TRUE`` and ``false``/``False``/``FALSE`` are booleans
  (PyYAML would also turn ``yes``/``no``/``on``/``off`` into booleans);
* only ``~``, ``null`` and the empty scalar are null;
* integers are anything ``i64::parse`` accepts (optional sign, ``0x``/``0o`` prefixes);
* floats keep their *original text* (``Yaml::Real(String)``), represented here by
  :class:`YamlReal` (a ``str`` subclass);
* dates such as ``2020-11-08`` stay strings (PyYAML would produce ``datetime.date``);
* everything else is a string.

Quoted scalars are always strings, exactly as in yaml-rust2.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import yaml

_LoaderBase = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

_ANY = re.compile(r".*", re.S)
_INT_RE = re.compile(r"^[-+]?[0-9]+$")
_F64_RE = re.compile(r"^[-+]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?$")
_I64_MIN, _I64_MAX = -(2**63), 2**63 - 1


class YamlReal(str):
    """A YAML float kept as its original text, like ``yaml_rust2::Yaml::Real``."""

    __slots__ = ()


def _parse_f64(value: str) -> bool:
    """Port of yaml-rust2's ``parse_f64`` (only whether it succeeds matters here)."""
    if value in {".inf", ".Inf", ".INF", "+.inf", "+.Inf", "+.INF", "-.inf", "-.Inf", "-.INF", ".nan", ".NaN", ".NAN"}:
        return True
    if not any(ch.isdigit() and ch.isascii() for ch in value):
        return False
    # Rust's f64 FromStr accepts decimal literals with an optional exponent (and "inf"/"nan",
    # which are excluded above by the digit requirement).
    return _F64_RE.match(value) is not None


_DIGITS = {10: re.compile(r"^[-+]?[0-9]+$"), 16: re.compile(r"^[-+]?[0-9a-fA-F]+$"), 8: re.compile(r"^[-+]?[0-7]+$")}


def _i64(text: str, base: int = 10) -> int | None:
    """Rust ``i64::from_str_radix``: optional sign, digits of the base only, must fit in i64."""
    if not _DIGITS[base].match(text):
        return None
    number = int(text, base)
    if _I64_MIN <= number <= _I64_MAX:
        return number
    return None


def scalar_from_str(value: str) -> Any:
    """Port of ``yaml_rust2::Yaml::from_str`` for plain (unquoted) scalars."""
    if value.startswith("0x"):
        number = _i64(value[2:], 16)
        if number is not None:
            return number
    elif value.startswith("0o"):
        number = _i64(value[2:], 8)
        if number is not None:
            return number
    elif value.startswith("+"):
        number = _i64(value[1:])
        if number is not None:
            return number
    if value in ("", "~", "null"):
        return None
    if value in ("true", "True", "TRUE"):
        return True
    if value in ("false", "False", "FALSE"):
        return False
    if _INT_RE.match(value):
        number = _i64(value)
        if number is not None:
            return number
    if _parse_f64(value):
        return YamlReal(value)
    return value


class HayabusaYamlLoader(_LoaderBase):  # type: ignore[misc,valid-type]
    """PyYAML loader whose plain scalars follow yaml-rust2's ``Yaml::from_str``."""


# Start from an empty resolver table so none of PyYAML's YAML 1.1 implicit types apply, then
# route every plain scalar through scalar_from_str().
HayabusaYamlLoader.yaml_implicit_resolvers = {}
HayabusaYamlLoader.add_implicit_resolver("!hayabusa/scalar", _ANY, None)


def _construct_scalar(loader: yaml.Loader, node: yaml.ScalarNode) -> Any:
    return scalar_from_str(loader.construct_scalar(node))


HayabusaYamlLoader.add_constructor("!hayabusa/scalar", _construct_scalar)


def load_all(text: str) -> Iterator[Any]:
    """Yield every YAML document in ``text`` (rule files may bundle several documents)."""
    return yaml.load_all(text, Loader=HayabusaYamlLoader)


def load(text: str) -> Any:
    """Load a single YAML document."""
    return yaml.load(text, Loader=HayabusaYamlLoader)


def is_hash(value: Any) -> bool:
    return isinstance(value, dict)


def is_vec(value: Any) -> bool:
    return isinstance(value, list)


def as_str(value: Any) -> str | None:
    """``Yaml::as_str``: only genuine strings (not YamlReal, not bool/int) count."""
    if isinstance(value, YamlReal):
        return None
    if isinstance(value, str):
        return value
    return None


def as_i64(value: Any) -> int | None:
    """``Yaml::as_i64``: integers only (bool is *not* an integer here)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def scalar_to_pattern(value: Any) -> str | None:
    """The rule-value-to-pattern conversion used by ``DefaultMatcher::init``.

    Boolean -> "true"/"false", Integer -> decimal text, Real -> original text, String -> itself,
    anything else (hash/array/null) -> None.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):  # includes YamlReal
        return str(value)
    return None
