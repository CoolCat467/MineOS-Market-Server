"""Market Server - MineOS App Market Server."""

# Programmed by CoolCat467

from __future__ import annotations

# Market Server - MineOS App Market Server
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

__title__ = "Market Server"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"

from typing import TYPE_CHECKING

from market_server.server import DATA_PATH, run

if TYPE_CHECKING:
    from trio import Path


def get_records_path() -> Path:
    """Return records path."""
    return DATA_PATH / "records"


if __name__ == "__main__":  # pragma: no cover
    run()
