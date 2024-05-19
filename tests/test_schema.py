from __future__ import annotations

from email.headerregistry import Address
from typing import Any

import pytest
from market_server import schema


@pytest.mark.parametrize(
    ("string", "expect"),
    [
        ("username@example.com", Address("", "username", "example.com")),
        (" username@example.com ", Address("", "username", "example.com")),
        ("username@beans@example.com", None),
        ("username@", None),
        ("@example.com", None),
        ("@", None),
        ("@.com", None),
        ("invalid email address", None),
    ],
)
def test_parse_email_address(string: str, expect: Address | None) -> None:
    assert schema.parse_email_address(string) == expect


@pytest.mark.parametrize(
    ("string", "expect"),
    [
        ("-5", -5),
        ("127", 127),
        ("3.14", None),
        ("0xff", None),
        (255, 255),
        (".57", None),
    ],
)
def test_parse_int(string: str | int, expect: int | None) -> None:
    assert schema.parse_int(string) == expect


@pytest.mark.parametrize(
    ("string", "expect"),
    [
        ("-5", {}),
        ("127=3", {"127": "3"}),
        ("pi=3.14", {"pi": "3.14"}),
        ("0xff", {}),
        ("0=zero&1=one", {"0": "zero", "1": "one"}),
        ("1=one&0=zero", {"0": "zero", "1": "one"}),
        ("[1]=one&[0]=zero", {"": {"0": "zero", "1": "one"}}),
        ("1[27]=one&0[6]=zero", {"0": {"6": "zero"}, "1": {"27": "one"}}),
    ],
)
def test_parse_table(string: str, expect: dict[str, Any]) -> None:
    assert schema.parse_table(string) == expect


@pytest.mark.parametrize(
    ("string", "expect"),
    [
        ("-5", []),
        ("127=3", []),
        ("pi=3.14", []),
        ("0xff", []),
        ("0=zero&1=one", []),
        ("1=one&0=zero", []),
        ("[1]=one&[0]=zero", []),
        ("1[27]=one&0[6]=zero", []),
        ("[27]=4&[6]=7", [4, 7]),  # sorted keys being strings
        ("[3]=27&[1]=49", [49, 27]),
        ("[0]=27&[1]=49", [27, 49]),
    ],
)
def test_parse_int_list(string: str, expect: list[int]) -> None:
    assert schema.parse_int_list(string) == expect
