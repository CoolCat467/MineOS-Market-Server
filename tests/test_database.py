import json
import tempfile
from collections.abc import Generator

import pytest

from market_server.database import Database, Records


@pytest.fixture
def temp_db_file() -> Generator[str, None, None]:
    # Create a temporary database file
    with tempfile.NamedTemporaryFile(delete=True) as temp_file:
        yield temp_file.name


def test_reload_file(temp_db_file: str) -> None:
    # Create a test database file with some data
    with open(temp_db_file, "w") as file:
        json.dump({"key": "value"}, file)

    # Initialize a Database instance and reload the file
    db = Database(temp_db_file, auto_load=False)
    db.reload_file()

    # Check if the data was loaded correctly
    assert db["key"] == "value"


@pytest.mark.trio
async def test_write_async(temp_db_file: str) -> None:
    # Initialize a Database instance
    db = Database(temp_db_file, auto_load=False)

    # Set some data
    db["key"] = "value"

    # Write the data asynchronously
    await db.write_async()

    # Check if the file was written correctly
    with open(temp_db_file) as file:  # noqa: ASYNC230
        data = json.load(file)
        assert data["key"] == "value"


@pytest.mark.trio
async def test_context_manager_async(temp_db_file: str) -> None:
    # Initialize a Database instance using async context manager
    async with Database(temp_db_file, auto_load=False) as db:
        db["jerald"] = "awesome"

    # Check if the file was written correctly after exiting the context manager
    with open(temp_db_file) as file:  # noqa: ASYNC230
        data = json.load(file)
        assert data["jerald"] == "awesome"


@pytest.mark.trio
async def test_table(temp_db_file: str) -> None:
    # Create a test database file with some data
    with open(temp_db_file, "w") as file:  # noqa: ASYNC230
        json.dump(
            {
                "key1": {"column1": "value1", "column2": "value2"},
                "key2": {"column1": "value3", "column2": "value4"},
            },
            file,
        )

    # Initialize a Table instance
    async with Records(temp_db_file) as records:
        table = records.table("keys")

        # Test accessing columns
        assert table["column1"] == ("value1", "value3")
        assert table["column2"] == ("value2", "value4")

        # Test setting column data
        table["column3"] = ("value5", "value6")
        assert table["column3"] == ("value5", "value6")


@pytest.mark.trio
async def test_records(temp_db_file: str) -> None:
    # Create a test database file with some data
    with open(temp_db_file, "w") as file:  # noqa: ASYNC230
        json.dump(
            {
                "key1": {"column1": "value1", "column2": "value2"},
                "key2": {"column1": "value3", "column2": "value4"},
            },
            file,
        )

    # Initialize a Records instance
    async with Records(temp_db_file) as records:
        table = records.table("keys")

        # Test accessing columns
        assert table["keys"] == ("key1", "key2")
        assert table["column1"] == ("value1", "value3")
        assert table["column2"] == ("value2", "value4")

        assert table.items() == (
            ("column1", ("value1", "value3")),
            ("column2", ("value2", "value4")),
            ("keys", ("key1", "key2")),
        )

        # Test setting column data
        records["key3"] = {"column1": "value5", "column2": "value6"}
        assert table["column1"] == ("value1", "value3", "value5")
        assert table["column2"] == ("value2", "value4", "value6")
