#!/usr/bin/env python3

"""Pretty-format json files."""

# Programmed by CoolCat467

from __future__ import annotations

# TITLE - DESCRIPTION
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

__title__ = "Pretty-format JSON"
__author__ = "CoolCat467"
__version__ = "0.0.0"
__license__ = "GNU General Public License Version 3"

import json


def run() -> None:
    """Run program."""
    for name in ("publications", "reviews"):
        with open(f"{name}.json") as fp:
            data = json.load(fp)
        with open(f"{name}.json", "w") as fp:
            json.dump(data, fp, sort_keys=True, indent=1)
    print("Action complete")


##def run() -> None:
##    "Run program"
##    with open("reviews.json", "r") as fp:
##        data = json.load(fp)
##    for file_id in data.keys():
##        reviews = data[file_id]
##        for review_id, review in reviews.items():
##            *first, (total, positive, _negative) = review
##            if _negative != 0:
##                raise RuntimeError("Negative is non-zero like we thought")
##            args = [*first, market_api.ReviewVotes(total=total, positive=positive)._asdict()]
##            kwargs = {k:v for k, v in zip(market_api.Review._fields, args)}
##            dict_ = market_api.Review(**kwargs)._asdict()
##            del dict_["id"]
##            reviews[review_id] = dict_
##        data[file_id] = reviews
##    with open("pretty.json", "w") as fp:
##        json.dump(data, fp, sort_keys=True, indent=1)
##    print("Action complete")


if __name__ == "__main__":
    print(f"{__title__} v{__version__}\nProgrammed by {__author__}.\n")
    run()
