"""Result - Potentially unsuccessful operation result."""

# Programmed by CoolCat467

from __future__ import annotations

# Result - Potentially unsuccessful operation result.
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

__title__ = "Result"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"


from typing import Generic, NamedTuple, TypeVar

T = TypeVar("T")


class Result(NamedTuple, Generic[T]):
    """Potentially unsuccessful operation result."""

    success: bool
    value: T

    @classmethod
    def ok(cls, value: T) -> Result[T]:
        """Success builder."""
        return cls(True, value)

    @classmethod
    def fail(cls, value: T) -> Result[T]:
        """Failure builder."""
        return cls(False, value)

    def __bool__(self) -> bool:
        """Return if successful."""
        return self.success

    def unwrap(self) -> T:
        """Return value."""
        return self.value
