"""Security functions like hashing passwords."""

# Programmed by CoolCat467

__title__ = "Security"
__author__ = "CoolCat467"

import base64
import hmac
import secrets
import time
from collections.abc import Callable
from functools import wraps
from hashlib import sha3_256 as _raw_sha3_256
from typing import TypeVar

import trio

_NEWEST_HASH: str = ""
_HASH_FUNCTIONS: dict[str, Callable[[str], str]] = {}

T = TypeVar("T")


def hash_function(func: Callable[[bytes], bytes]) -> Callable[[str], str]:
    """Register hash function.

    Note that arguments change from bytes to string and so does return value,
    and help() results will not match up with this.
    """
    global _NEWEST_HASH  # pylint: disable=global-statement

    assign = ("__module__", "__name__", "__qualname__", "__doc__")
    update = ("__dict__",)

    @wraps(func, assign, updated=update)
    def wrapped(string: str) -> str:
        """Return base64 encode of hashed version of given string."""
        bytes_ = func(string.encode("utf-8"))
        return base64.b64encode(bytes_).decode("utf-8")

    name = func.__name__

    _HASH_FUNCTIONS[name] = wrapped
    _NEWEST_HASH = name
    return wrapped


def get_hash(hash_name: str, value: str) -> str:
    """Get hash of value using hash name function."""
    if hash_name not in _HASH_FUNCTIONS:
        raise ValueError(
            f'No function named "{hash_name}" has '
            + "the @hash_function decorator",
        )
    return _HASH_FUNCTIONS[hash_name](value)


@hash_function
def sha3_256(bytes_: bytes) -> bytes:
    """Get SHA3 256 hash of string."""
    hash_obj = _raw_sha3_256(bytes_)
    return hash_obj.digest()


def hash_login(
    password: str,
    salt: str,
    hash_func_name: str,
    pepper: str,
) -> str:
    """Return hash of login information."""
    hash_ = get_hash(hash_func_name, f"{pepper}{salt}{password}")

    return f"{hash_func_name}${salt}${hash_}"


def generate_salt() -> str:
    """Generate random salt."""
    return secrets.token_urlsafe(32)


def create_new_login_credentials(password: str, pepper: str) -> str:
    """Return new login credentials given password and global pepper."""
    return hash_login(password, generate_salt(), _NEWEST_HASH, pepper)


def get_password_hash_for_compare(
    password: str,
    database_value: str,
    pepper: str,
) -> tuple[str, str]:
    """Return tuple of database hash and password hash."""
    hash_name, rest = database_value.split("$", 1)
    if hash_name in {"sha3_256"}:
        # If hash algorithm in set of ones that store salt with database value
        salt = rest.split("$", 1)[0]
        return database_value, hash_login(password, salt, hash_name, pepper)
    raise ValueError(
        f"Exhaustive list of hash_name exhausted, got unhandled {hash_name!r}",
    )


def compare_hash_time_attackable(
    password: str,
    database_value: str,
    pepper: str,
) -> bool:
    """Compare password and database value in variable time.

    This can lead to people figuring out password because string
    equality is smart and skips checking the rest of two strings
    the instant the two characters don't match, so by carefully
    timing the response, attackers could figure out the password
    character by character
    """
    recorded, new_hash = get_password_hash_for_compare(
        password,
        database_value,
        pepper,
    )
    return recorded == new_hash


def compare_hash_sync(password: str, database_value: str, pepper: str) -> bool:
    """Compare password and database value in a constant amount of time."""
    recorded, new_hash = get_password_hash_for_compare(
        password,
        database_value,
        pepper,
    )
    return hmac.compare_digest(recorded, new_hash)


async def compare_hash(
    password: str,
    database_value: str,
    pepper: str,
) -> bool:
    """Compare password and database value in a constant amount of time."""
    # 1 millisecond is 1e+6 nanoseconds
    target = 2e6  # Probably fine given ~136403ns test, order of magnitude up
    start = time.perf_counter_ns()
    recorded, new_hash = get_password_hash_for_compare(
        password,
        database_value,
        pepper,
    )
    is_equal = recorded == new_hash
    end = time.perf_counter_ns()
    # Sleep for at least target nanoseconds (divide by 1e+9 -> seconds)
    await trio.sleep(max(0, target - (end - start)) / 1e9)
    # THEN return result
    return is_equal


def create_new_password(min_length: int) -> str:
    """Create a new secure password."""
    return secrets.token_urlsafe(min_length)


# def time_function(
#     function: Callable[..., T], *args: Any, **kwargs: Any
# ) -> tuple[T, int]:
#     """Time function execution"""
#     start = time.perf_counter_ns()
#     value = function(*args, **kwargs)
#     end = time.perf_counter_ns()
#     return value, end - start


# async def time_function_async(
#     function: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any
# ) -> tuple[T, int]:
#     """Time asynchronous function execution"""
#     start = time.perf_counter_ns()
#     value = await function(*args, **kwargs)
#     end = time.perf_counter_ns()
#     return value, end - start
