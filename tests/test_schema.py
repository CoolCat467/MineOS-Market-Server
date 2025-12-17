from __future__ import annotations

from email.headerregistry import Address
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
import trio

from market_server import database, schema

if TYPE_CHECKING:
    from pathlib import Path


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
        ({"127": "3"}, {"127": "3"}),
        ({"pi": "3.14"}, {"pi": "3.14"}),
        ({"0": "zero", "1": "one"}, {"0": "zero", "1": "one"}),
        ({"[1]": "one", "[0]": "zero"}, {"": {"0": "zero", "1": "one"}}),
        (
            {"1[27]": "one", "0[6]": "zero"},
            {"0": {"6": "zero"}, "1": {"27": "one"}},
        ),
    ],
)
def test_parse_table(  # type: ignore[misc]
    string: dict[str, str],
    expect: dict[str, Any],
) -> None:
    assert schema.parse_table(string, None) == expect


@pytest.mark.parametrize(
    ("string", "expect"),
    [
        ({"127": "3"}, [3]),
        ({"pi": "3.14"}, []),
        ({"0": "zero", "1": "one"}, []),
        ({"[1]": "one", "[0]": "zero"}, []),
        ({"1[27]": "one", "0[6]": "zero"}, []),
        ({"[27]": "4", "[6]": "7"}, [4, 7]),  # sorted keys being strings
        ({"[3]": "27", "[1]": "49"}, [49, 27]),
        ({"[0]": "27", "[1]": "49"}, [27, 49]),
    ],
)
def test_parse_int_list(string: dict[str, str], expect: list[int]) -> None:
    assert schema.parse_int_list(string) == expect


@pytest.fixture
def schema_v204(tmp_path: Path) -> schema.Version_2_04:
    return schema.Version_2_04(trio.Path(tmp_path))


@pytest.mark.trio
async def test_cmd_register_and_verify(
    schema_v204: schema.Version_2_04,
) -> tuple[str, str, str]:
    name = "test_username"
    email = "noreply@gmail.com"
    password = "test_password"  # noqa: S105

    with patch(
        "market_server.schema.send_email",
        return_value=None,
    ):
        result = await schema_v204.cmd_register(name, email, password)
    assert (
        result
        == f"{{success=true,result='Check your e-mail ({email}) and spam folder message to submit your MineOS account'}}"
    )

    users = await database.load_async(schema_v204.users_path)
    verify_token = users[name]["verify_token"]

    assert await schema_v204.verify(verify_token)

    return (name, email, password)


@pytest.mark.trio
async def test_cmd_login(schema_v204: schema.Version_2_04) -> str:
    name, email, password = await test_cmd_register_and_verify(schema_v204)

    response = await schema_v204.cmd_login(None, name, password)

    assert isinstance(response, str)
    assert "token='" in response
    token = response.split("token='", 1)[1].split("'", 1)[0]

    assert response.startswith(
        f"{{success=true,result={{id=0,token='{token}',name='{name}',email='{email}',is_verified=true,timestamp=",
    )
    assert response.endswith("}}")

    return token


@pytest.mark.trio
async def test_cmd_change_password(schema_v204: schema.Version_2_04) -> None:
    new_password = "tac nyan is a waffle cat"  # noqa: S105
    name, email, current_password = await test_cmd_register_and_verify(
        schema_v204,
    )

    response = await schema_v204.cmd_change_password(
        email,
        current_password,
        new_password,
    )
    assert response == "{success=true}"

    response = await schema_v204.cmd_login(None, name, new_password)

    assert "token='" in response


@pytest.fixture
async def token(
    schema_v204: schema.Version_2_04,
) -> tuple[schema.Version_2_04, str]:
    return (schema_v204, await test_cmd_login(schema_v204))
