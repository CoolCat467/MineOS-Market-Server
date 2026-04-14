"""Unit tests for server_utils module."""

from __future__ import annotations

from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from werkzeug.exceptions import Forbidden, NotFound

from market_server.server_utils import (
    find_ip,
    get_exception_page,
    pretty_exception,
    pretty_exception_name,
    send_error,
)


@pytest.mark.trio
async def test_send_error_basic() -> None:
    """Test send_error with basic parameters."""
    with patch(
        "market_server.server_utils.stream_template",
        new_callable=AsyncMock,
    ) as mock_stream:
        mock_stream.return_value = "error page content"

        result = await send_error(
            page_title="Test Error",
            error_body="Something went wrong",
        )

        mock_stream.assert_called_once_with(
            "error_page.html.jinja",
            page_title="Test Error",
            error_body="Something went wrong",
            return_link=None,
        )
        assert cast("str", result) == "error page content"


@pytest.mark.trio
async def test_send_error_with_return_link() -> None:
    """Test send_error with return link."""
    with patch(
        "market_server.server_utils.stream_template",
        new_callable=AsyncMock,
    ) as mock_stream:
        mock_stream.return_value = "error page with link"

        result = await send_error(
            page_title="404 Not Found",
            error_body="Page not found",
            return_link="/home",
        )

        mock_stream.assert_called_once_with(
            "error_page.html.jinja",
            page_title="404 Not Found",
            error_body="Page not found",
            return_link="/home",
        )
        assert cast("str", result) == "error page with link"


@pytest.mark.trio
async def test_get_exception_page_basic() -> None:
    """Test get_exception_page returns correct structure."""
    with patch(
        "market_server.server_utils.send_error",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = "error content"

        body, code = await get_exception_page(
            code=404,
            name="Not Found",
            desc="The requested resource was not found",
        )

        assert code == 404
        assert cast("str", body) == "error content"
        mock_send.assert_called_once_with(
            page_title="404 Not Found",
            error_body="The requested resource was not found",
            return_link=None,
        )


@pytest.mark.trio
async def test_get_exception_page_with_return_link() -> None:
    """Test get_exception_page with return link."""
    with patch(
        "market_server.server_utils.send_error",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = "error content"

        _body, code = await get_exception_page(
            code=403,
            name="Forbidden",
            desc="Access denied",
            return_link="/",
        )

        assert code == 403
        mock_send.assert_called_once_with(
            page_title="403 Forbidden",
            error_body="Access denied",
            return_link="/",
        )


@pytest.mark.trio
async def test_get_exception_page_various_codes() -> None:
    """Test get_exception_page with various HTTP codes."""
    codes = [400, 401, 403, 404, 500, 502, 503]

    with patch(
        "market_server.server_utils.send_error",
        new_callable=AsyncMock,
    ) as mock_send:
        mock_send.return_value = "error"

        for code in codes:
            _, returned_code = await get_exception_page(
                code=code,
                name="Error",
                desc="Description",
            )
            assert returned_code == code


class CustomError(Exception):
    """Custom error for testing."""

    __slots__ = ()


class VeryLongCustomErrorNameError(Exception):
    """Error with long name."""

    __slots__ = ()


def test_pretty_exception_name_standard_error() -> None:
    """Test pretty_exception_name with standard exceptions."""
    exc = ValueError("invalid value")
    result = pretty_exception_name(exc)
    assert "Value" in result
    assert "invalid value" in result


def test_pretty_exception_name_custom_error() -> None:
    """Test pretty_exception_name with custom exception."""
    exc = CustomError("test reason")
    result = pretty_exception_name(exc)
    assert "Custom" in result
    assert "test reason" in result
    assert "Error" not in result  # Error suffix is filtered


def test_pretty_exception_name_removes_error_suffix() -> None:
    """Test that Error and Exception suffixes are removed."""
    exc = RuntimeError("problem")
    result = pretty_exception_name(exc)
    assert "Runtime" in result
    assert "Error" not in result
    assert "problem" in result


def test_pretty_exception_name_type_error() -> None:
    """Test pretty_exception_name with TypeError."""
    exc = TypeError("expected string")
    result = pretty_exception_name(exc)
    assert "Type" in result
    assert "expected string" in result


def test_pretty_exception_name_attribute_error() -> None:
    """Test pretty_exception_name with AttributeError."""
    exc = AttributeError("no attribute")
    result = pretty_exception_name(exc)
    assert "Attribute" in result
    assert "no attribute" in result


def test_pretty_exception_name_multiple_words() -> None:
    """Test pretty_exception_name with multi-word exception."""
    exc = VeryLongCustomErrorNameError("test")
    result = pretty_exception_name(exc)
    assert "Very" in result
    assert "Long" in result
    assert "Custom" in result
    assert "test" in result


def test_pretty_exception_name_empty_reason() -> None:
    """Test pretty_exception_name with no reason."""
    # Create an exception with no args
    exc = ValueError()
    result = pretty_exception_name(exc)
    assert "Value" in result


@pytest.mark.trio
async def test_pretty_exception_success() -> None:
    """Test pretty_exception decorator with successful function."""

    @pretty_exception
    async def successful_function() -> str:
        return "success"

    result = await successful_function()
    assert result == "success"


@pytest.mark.trio
async def test_pretty_exception_with_args_and_kwargs() -> None:
    """Test pretty_exception preserves function arguments."""

    @pretty_exception
    async def function_with_args(
        a: int,
        b: int,
        c: int | None = None,
    ) -> tuple[int, int, int | None]:
        return (a, b, c)

    result = await function_with_args(1, 2, c=3)
    assert result == (1, 2, 3)


@pytest.mark.trio
async def test_pretty_exception_catches_generic_exception() -> None:
    """Test pretty_exception catches and formats generic exceptions."""

    @pretty_exception
    async def failing_function() -> None:
        raise ValueError("test error")

    with patch(
        "market_server.server_utils.get_exception_page",
        new_callable=AsyncMock,
    ) as mock_page:
        mock_page.return_value = ("error page", 500)

        result = await failing_function()

        assert cast("tuple[str, int]", result) == ("error page", 500)
        # Verify get_exception_page was called with 500 and appropriate error name
        call_args = mock_page.call_args
        assert call_args[0][0] == 500  # code
        assert "Value" in call_args[0][1]  # name contains "Value"


@pytest.mark.trio
async def test_pretty_exception_catches_http_exception() -> None:
    """Test pretty_exception catches HTTPException."""

    @pretty_exception
    async def http_error_function() -> None:
        raise NotFound("Resource not found")

    with patch(
        "market_server.server_utils.get_exception_page",
        new_callable=AsyncMock,
    ) as mock_page:
        mock_page.return_value = ("error page", 404)

        result = await http_error_function()

        assert cast("tuple[str, int]", result) == ("error page", 404)
        call_args = mock_page.call_args
        # code from HTTPException
        assert call_args[0][0] == 404
        # name from HTTPException
        assert call_args[0][1] == "Not Found"


@pytest.mark.trio
async def test_pretty_exception_catches_forbidden() -> None:
    """Test pretty_exception with Forbidden exception."""

    @pretty_exception
    async def forbidden_function() -> None:
        raise Forbidden("Access denied")

    with patch(
        "market_server.server_utils.get_exception_page",
        new_callable=AsyncMock,
    ) as mock_page:
        mock_page.return_value = ("error page", 403)

        await forbidden_function()

        call_args = mock_page.call_args
        assert call_args[0][0] == 403


@pytest.mark.trio
async def test_pretty_exception_default_error_message() -> None:
    """Test pretty_exception uses default message for non-HTTP exceptions."""

    @pretty_exception
    async def error_function() -> None:
        raise RuntimeError("something broke")

    with patch(
        "market_server.server_utils.get_exception_page",
        new_callable=AsyncMock,
    ) as mock_page:
        mock_page.return_value = ("error page", 500)

        await error_function()

        call_args = mock_page.call_args
        assert call_args[0][0] == 500
        # Should contain custom error name for non-HTTP exceptions
        assert "Runtime" in call_args[0][1]


@pytest.mark.trio
async def test_pretty_exception_prints_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Test pretty_exception prints exception traceback."""

    @pretty_exception
    async def error_function() -> None:
        raise ValueError("test error")

    with patch(
        "market_server.server_utils.get_exception_page",
        new_callable=AsyncMock,
    ) as mock_page:
        mock_page.return_value = ("error page", 500)

        await error_function()

        captured = capsys.readouterr()
        # Traceback should be printed to stdout/stderr
        assert "ValueError" in captured.out or "ValueError" in captured.err


@pytest.mark.trio
async def test_pretty_exception_preserves_function_name() -> None:
    """Test pretty_exception preserves original function name."""

    @pretty_exception
    async def original_function() -> str:
        return "result"

    assert original_function.__name__ == "original_function"


def test_find_ip_returns_string() -> None:
    """Test find_ip returns a string."""
    result = find_ip()
    assert isinstance(result, str)


def test_find_ip_returns_valid_ipv4() -> None:
    """Test find_ip returns valid IPv4 address."""
    result = find_ip()
    parts = result.split(".")
    assert len(parts) == 4
    for part in parts:
        num = int(part)
        assert 0 <= num <= 255


def test_find_ip_connects_to_test_networks() -> None:
    """Test find_ip attempts to connect to IANA test networks."""
    with patch(
        "market_server.server_utils.socket.socket",
    ) as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.getsockname.return_value = ("192.168.1.100", 12345)

        result = find_ip()

        # Should have attempted connections to test networks
        assert mock_socket_class.call_count == 2
        assert result == "192.168.1.100"
        # Verify close was called
        assert mock_socket.close.call_count == 2


def test_find_ip_returns_duplicate_ip() -> None:
    """Test find_ip returns IP when duplicate found (optimization)."""
    with patch(
        "market_server.server_utils.socket.socket",
    ) as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        # Return same IP on first two calls
        mock_socket.getsockname.side_effect = [
            ("192.168.1.100", 12345),
            ("192.168.1.100", 12345),
            ("192.168.1.101", 12345),
        ]

        result = find_ip()

        # Should return on second call when duplicate is found
        assert result == "192.168.1.100"
        # Should only try twice (first + second which is duplicate)
        assert mock_socket_class.call_count == 2


def test_find_ip_fallback_to_first() -> None:
    """Test find_ip returns first candidate if no duplicates."""
    with patch(
        "market_server.server_utils.socket.socket",
    ) as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        # Return different IPs each time
        mock_socket.getsockname.side_effect = [
            ("192.168.1.100", 12345),
            ("192.168.1.101", 12345),
            ("192.168.1.102", 12345),
        ]

        result = find_ip()

        # Should return first candidate
        assert result == "192.168.1.100"
        assert mock_socket_class.call_count == 3


def test_find_ip_socket_configuration() -> None:
    """Test find_ip uses correct socket configuration."""
    with patch(
        "market_server.server_utils.socket.socket",
    ) as mock_socket_class:
        import socket as socket_module

        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.getsockname.return_value = ("10.0.0.1", 12345)

        find_ip()

        # Should use AF_INET and SOCK_DGRAM
        mock_socket_class.assert_called_with(
            socket_module.AF_INET,
            socket_module.SOCK_DGRAM,
        )


def test_find_ip_connects_to_correct_addresses() -> None:
    """Test find_ip tries to connect to IANA test networks."""
    test_ips = ("192.0.2.0", "198.51.100.0")

    with patch(
        "market_server.server_utils.socket.socket",
    ) as mock_socket_class:
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        mock_socket.getsockname.return_value = ("10.0.0.1", 12345)

        find_ip()

        # Verify connect was called with each test IP
        for call, test_ip in zip(
            mock_socket.connect.call_args_list,
            test_ips,
            strict=True,
        ):
            assert call.args == ((test_ip, 80),)
