"""API Module - Convert python objects to lua."""

# Programmed by CoolCat467

from __future__ import annotations

# API Module - Convert python objects to lua
# Copyright (C) 2024  CoolCat467
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__title__ = "API Module"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"


from typing import TYPE_CHECKING, NamedTuple, TypeVar, cast

if TYPE_CHECKING:
    from collections.abc import Generator

T = TypeVar("T")


def parse_int(string: str) -> int | None:
    """Try to parse int. Return None on failure."""
    try:
        return int(string)
    except ValueError:
        return None


def dict_to_fields(
    dict_: dict[object, T],
) -> Generator[tuple[str, T], None, None]:
    """Yield field (exp|Name, exp) tuples."""
    for key, value in dict_.items():
        if isinstance(key, str) and parse_int(key) is None:
            yield key, value
            continue
        yield f"[{as_lua(key)}]", value


def as_lua(object_: object, ignore_none: bool = False) -> str:
    """Return lua representation of python object.

    See https://www.lua.org/manual/5.4/manual.html#9 for more details.
    """
    match object_:
        case None:
            return "nil"
        case bool():
            return str(object_).lower()
        case str():
            return repr(object_)
        case float():
            return repr(object_)
        case int():
            return repr(object_)
        case dict():
            fieldlist = ",".join(
                f"{key}={as_lua(value)}"
                for key, value in dict_to_fields(object_)
                if not ignore_none or value is not None
            )
            return f"{{{fieldlist}}}"
        case list():
            fieldlist = ",".join(as_lua(value) for value in object_)
            return f"{{{fieldlist}}}"
        case tuple():
            if hasattr(object_, "_asdict"):
                return as_lua(object_._asdict())
            raise ValueError(f"Non-named tuple {object_!r}")
        case _:
            raise NotImplementedError(type(object_))


def response(ignore_none: bool, /, **kwargs: object) -> str:
    """Return lua table from keyword arguments."""
    return as_lua(kwargs, ignore_none=ignore_none)


def failure(reason: str, http_code: int = 400) -> tuple[str, int]:
    """Return lua api failure table along with http response code."""
    return response(False, success=False, reason=reason), http_code


Response = str | tuple[str, int]


def success_direct(result: object, ignore_none: bool = False) -> str:
    """Return lua api success table where you can set result directly."""
    return response(ignore_none, success=True, result=result)


def success(**kwargs: object) -> str:
    """Return lua api success table."""
    if kwargs:
        return response(False, success=True, result=kwargs)
    return response(False, success=True)


def success_schema(response: NamedTuple, ignore_none: bool = True) -> str:
    """Return lua api success table from named tuple."""
    as_dict = {k: v for k, v in response._asdict().items() if v is not None}
    return success_direct(
        cast(dict[object, object], as_dict),
        ignore_none=ignore_none,
    )


if __name__ == "__main__":  # pragma: no cover
    print(f"{__title__}\nProgrammed by {__author__}.\n")
