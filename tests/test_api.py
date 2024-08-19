from __future__ import annotations

from typing import NamedTuple

import pytest

from market_server import api


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
    assert api.parse_int(string) == expect


@pytest.mark.parametrize(
    ("string", "expect"),
    [
        ("-5", "'-5'"),
        (-5, "-5"),
        ("127", "'127'"),
        ("3.14", "'3.14'"),
        (3.14, "3.14"),
        ("0xff", "'0xff'"),
        (255, "255"),
        (".57", "'.57'"),
        (True, "true"),
        (False, "false"),
        ({"pi": 3.14}, "{pi=3.14}"),
        ({"array": {"pi": 3.14}}, "{array={pi=3.14}}"),
        ({"success": True}, "{success=true}"),
        ({"file_ids": [28, 5, 29, 54]}, "{file_ids={28,5,29,54}}"),
        (
            {0: "zero", 1: "one", 27: "twenty seven"},
            "{[0]='zero',[1]='one',[27]='twenty seven'}",
        ),
    ],
)
def test_as_lua(string: object, expect: str) -> None:
    assert api.as_lua(string) == expect


def test_as_lua_namedtuple() -> None:
    class Value(NamedTuple):
        name: str
        arguments: list[int]

    obj = Value("Object name", [1, 2, 5, 7, 9])
    assert api.as_lua(obj) == "{name='Object name',arguments={1,2,5,7,9}}"


def test_success_schema() -> None:
    class Value(NamedTuple):
        name: str | None
        arguments: list[int]

    obj = Value(None, [1, 2, 5, 7, 9])
    assert (
        api.success_schema(obj)
        == "{success=true,result={arguments={1,2,5,7,9}}}"
    )


def test_as_lua_bad_tuple() -> None:
    with pytest.raises(ValueError, match=r"Non-named tuple \(1, 2, 3\)"):
        api.as_lua((1, 2, 3))


def test_as_lua_bad_value() -> None:
    with pytest.raises(NotImplementedError, match=r"set"):
        api.as_lua({1, 2, 3})


def test_failure() -> None:
    assert api.failure("Internal Server Error", 500) == (
        "{success=false,reason='Internal Server Error'}",
        500,
    )


def test_success_direct() -> None:
    assert (
        api.success_direct({"file_ids": [28, 5, 29, 54, None]})
        == "{success=true,result={file_ids={28,5,29,54,nil}}}"
    )


def test_success() -> None:
    assert (
        api.success(waffles="very tasty")
        == "{success=true,result={waffles='very tasty'}}"
    )
    assert api.success() == "{success=true}"
