"""Test security module."""

import random
import secrets
from typing import TYPE_CHECKING

import pytest

from market_server import security

if TYPE_CHECKING:
    from collections.abc import Callable


@pytest.fixture(autouse=True)
def _no_random(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace secrets sysrand with new Random object with seed 1234."""
    monkeypatch.setattr(secrets, "_sysrand", random.Random(1234))  # noqa: S311


def test_hash_function(monkeypatch: pytest.MonkeyPatch) -> None:
    functions: dict[str, Callable[[str], str]] = {}
    monkeypatch.setattr(security, "_NEWEST_HASH", "")
    monkeypatch.setattr(security, "_HASH_FUNCTIONS", functions)

    @security.hash_function
    def func_hash_name(bytes_: bytes) -> bytes:
        return bytes_

    assert set(functions) == {"func_hash_name"}


def test_get_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    functions = {"noop_hash": lambda x: "output"}
    monkeypatch.setattr(security, "_HASH_FUNCTIONS", functions)

    assert security.get_hash("noop_hash", "input value") == "output"


def test_get_hash_bad_funcname() -> None:
    with pytest.raises(
        ValueError,
        match='No function named "does not exist hash" has the @hash_function decorator',
    ):
        security.get_hash("does not exist hash", "input value")


def test_sha3_256() -> None:
    assert (
        security.sha3_256("cat")
        == "1hZgfT5LqWp08yPP/F8go8eOfKuOy9uwOxP6j/yb9kQ="
    )


def test_hash_login_sha3_256() -> None:
    assert (
        security.hash_login(
            "cat",
            "this is salt",
            "sha3_256",
            "this is pepper",
        )
        == "sha3_256$this is salt$9QXdX8O+oqnQIXWshz251oGOQftoVrfVhfH99F+61C8="
    )


def test_generate_salt() -> None:
    assert (
        security.generate_salt()
        == "uX9p917fNccf2tNwZurpHRT26gFFazQXcLg16UL1SfE"
    )


def test_create_new_login_credentials() -> None:
    assert (
        security.create_new_login_credentials("password", "is pepper")
        == "sha3_256$uX9p917fNccf2tNwZurpHRT26gFFazQXcLg16UL1SfE$GYDwBwZIOXJUitMMhxUWw12JGRj/yRi8oE+Zi/Sqh2s="
    )


def test_get_password_hash_for_compare_bad_funcname() -> None:
    with pytest.raises(
        ValueError,
        match="Exhaustive list of hash_name exhausted, got unhandled 'fish_64'",
    ):
        security.get_password_hash_for_compare(
            "fish",
            "fish_64$salt$seven",
            "peppers",
        )


def test_get_password_hash_for_compare_diff_pepper() -> None:
    assert security.get_password_hash_for_compare(
        "tomato",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "peppers",
    ) == (
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$QuNHWvhiupy/eSdtwNuyKWtUj38Cpo15Z3O/Uj0hOBU=",
    )


def test_get_password_hash_for_compare_diff() -> None:
    assert security.get_password_hash_for_compare(
        "fish",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "peppers",
    ) == (
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$2/I5zpmgJdZX6sG7uJQfHXXOtvElpZpI0d0BJd3LZfo=",
    )


def test_get_password_hash_for_compare_same_pepper() -> None:
    assert security.get_password_hash_for_compare(
        "tomato",
        "sha3_256$vNZOW3uyTIVUaRSXI7q7QGi_3h1mg0VKzjVD0zmAedk$8kGVye+TgVSqvqoRL9hJfRU3+79vefcZb8rppT/LBz4=",
        "peppers",
    ) == (
        "sha3_256$vNZOW3uyTIVUaRSXI7q7QGi_3h1mg0VKzjVD0zmAedk$8kGVye+TgVSqvqoRL9hJfRU3+79vefcZb8rppT/LBz4=",
        "sha3_256$vNZOW3uyTIVUaRSXI7q7QGi_3h1mg0VKzjVD0zmAedk$EeaQnWq3n4MNR+zOiygLKsj32kyjwu8C64vWNK94q7o=",
    )


def test_compare_hash_time_attackable_bad_password() -> None:
    assert not security.compare_hash_time_attackable(
        "super passwords",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "peppers",
    )


def test_compare_hash_time_attackable_different_pepper() -> None:
    assert not security.compare_hash_time_attackable(
        "totatoe",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "different",
    )


def test_compare_hash_time_attackable_correct() -> None:
    assert security.compare_hash_time_attackable(
        "totatoe",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "peppers",
    )


def test_compare_hash_sync_bad_password() -> None:
    assert not security.compare_hash_sync(
        "super passwords",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "peppers",
    )


def test_compare_hash_sync_different_pepper() -> None:
    assert not security.compare_hash_sync(
        "totatoe",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "different",
    )


def test_compare_hash_sync_correct() -> None:
    assert security.compare_hash_sync(
        "totatoe",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "peppers",
    )


@pytest.mark.trio
async def test_compare_hash_correct() -> None:
    assert await security.compare_hash(
        "totatoe",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "peppers",
    )


@pytest.mark.trio
async def test_compare_hash_wrong() -> None:
    assert not await security.compare_hash(
        "hacks password",
        "sha3_256$GqpVN8aXBHRspMd04vIsOm4P-6UNixCHdUiqblydVpo$eA5A53S/Kl11r7a9Q9YzjBVUDuh4i4Nn0cNl282+Xts=",
        "peppers",
    )


def test_create_new_password() -> None:
    assert security.create_new_password(12) == "uX9p917fNccf2tNw"
