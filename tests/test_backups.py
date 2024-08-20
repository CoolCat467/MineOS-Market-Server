from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest
import trio

from market_server import backups

if TYPE_CHECKING:
    from types import TracebackType

    from market_server import database


@pytest.mark.trio
async def test_backup_database() -> None:
    # Mock database.get_loaded() function to return a list of loaded database filenames
    with patch(
        "market_server.database.get_loaded",
        return_value=["database1"],
    ):
        # Mock database.load() function to return a database instance
        with patch("market_server.database.load") as mock_load:
            mock_instance = Mock()
            mock_load.side_effect = lambda db_name: (
                mock_instance if db_name == "database1" else None
            )

            # Mock database.Database() context manager to simulate loading and unloading a database
            with patch("market_server.database.Database") as mock_database:
                # Define __aenter__ and __aexit__ methods for the mock object
                async def async_enter(
                    self: database.Database,
                ) -> database.Database:
                    return self

                async def async_exit(
                    self: database.Database,
                    exc_type: type[BaseException] | None,
                    exc_value: BaseException | None,
                    traceback: TracebackType | None,
                ) -> None:
                    pass

                mock_backup_instance = Mock()
                mock_backup_instance.__aenter__ = async_enter
                mock_backup_instance.__aexit__ = async_exit
                mock_database.side_effect = lambda db_name, auto_load=False: (
                    mock_backup_instance if db_name.endswith(".bak") else None
                )

                # Call the backup_database function
                await backups.backup_database()

                # Assertions
                mock_load.assert_called_once()  # Check if database.load() was called once
                mock_backup_instance.clear.assert_called_once()  # Check if backup.clear() was called once
                mock_backup_instance.update.assert_called_once_with(
                    mock_instance,
                )  # Check if backup.update() was called with the correct instance


@pytest.mark.trio
async def test_backup() -> None:
    with patch.object(logging, "info") as mock_info:
        with patch.object(backups, "backup_database") as mock_backup_database:
            await backups.backup()
            mock_backup_database.assert_called_once()
            mock_info.assert_called_with("Backup complete")


@pytest.mark.trio
async def test_periodic_backups(
    autojump_clock: trio.testing.MockClock,
) -> None:
    with patch.object(backups, "backup") as mock_backup:
        async with trio.open_nursery() as nursery:
            # Start the periodic_backups function in the trio nursery
            nursery.start_soon(backups.periodic_backups)

            # Allow some time for Trio to execute pending tasks
            await trio.testing.wait_all_tasks_blocked()

            # Advance the clock by 6 hours and 1 sec to trigger the periodic backup
            autojump_clock.jump(60 * 60 * 6 + 1)

            # Allow some time for Trio to execute pending tasks
            await trio.testing.wait_all_tasks_blocked()

            nursery.cancel_scope.cancel()

        # Assert that the backup function was called at least once
        mock_backup.assert_called_once()
