"""Backups - Perform periodic backups of all records."""

# Programmed by CoolCat467

from __future__ import annotations

# Backups - Perform periodic backups of all records
# Copyright (C) 2023  CoolCat467
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

__title__ = "Backups"
__author__ = "CoolCat467"

import logging
import time
from os import path

import trio
from ciastore import csvrecords, database


async def backup_database() -> None:
    """Backup records from database module."""
    for database_name in database.get_loaded():
        # Get folder and filename
        folder = path.dirname(database_name)
        orig_filename = path.basename(database_name)

        # Attempt to get list of [{filename}, {file end}]
        file_parts = orig_filename.rsplit(".", 1)
        if len(file_parts) == 2:
            # End exists
            name, end = file_parts
            # If is already a backup, do not backup the backup.
            # If this happens that is bad.
            if "bak" in end:
                continue
            end = f"{end}.bak"
        else:
            # If end not exist, just make it a backup file
            name = file_parts[0]
            end = "bak"

        # We have now gotten name and end, add time stamp to name
        name = time.strftime(f"{name}_(%Y_%m_%d)")
        filename = f"{name}.{end}"

        # Get full path of backup file
        backup_name = path.join(folder, "backup", filename)

        # Load up file to take backup of and new backup file
        instance = database.load(database_name)
        backup = database.load(backup_name)

        # Add contents of original to backup
        backup.clear()
        backup.update(instance)

        # Unload backup file which triggers it to write,
        # including creating folders if it has to
        database.unload(backup_name)


async def backup_csv() -> None:
    """Backup records from csvrecords module."""
    async with trio.open_nursery() as nursery:
        for csvrecord_name in csvrecords.get_loaded():
            # Get folder and filename
            folder = path.dirname(csvrecord_name)
            orig_filename = path.basename(csvrecord_name)

            # Attempt to get list of [{filename}, {file end}]
            file_parts = orig_filename.rsplit(".", 1)
            if len(file_parts) == 2:
                # End exists
                name, end = file_parts
                # If is already a backup, do not backup the backup.
                # If this happens that is bad.
                if "bak" in end:
                    continue
                end = f"{end}.bak"
            else:
                # If end not exist, just make it a backup file
                name = file_parts[0]
                end = "bak"

            # We have now gotten name and end, add time stamp to name
            name = time.strftime(f"{name}_(%Y_%m_%d)")
            filename = f"{name}.{end}"

            # Get full path of backup file
            backup_name = path.join(folder, "backup", filename)

            # Load up file to take backup of and new backup file
            instance = csvrecords.load(csvrecord_name, None)
            backup = csvrecords.load(backup_name, instance.key_name)

            # Add contents of original to backup
            backup.clear()
            backup.update(instance)

            # Unload backup file which triggers it to write,
            # including creating folders if it has to
            nursery.start_soon(csvrecords.unload, backup_name)


async def backup() -> None:
    """Backup all records."""
    logging.info("Performing backup")
    await backup_database()
    await backup_csv()
    logging.info("Backup complete")


async def periodic_backups() -> None:
    """Trigger periodic backups."""
    while True:
        # Do backup every 6 hours
        await trio.sleep(60 * 60 * 6)
        await backup()


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
