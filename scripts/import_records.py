"""Import Records - Import records from remote MineOS Market API."""

# Programmed by CoolCat467

from __future__ import annotations

# Import Records - Import records from remote MineOS Market API.
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

__title__ = "Import Records"
__author__ = "CoolCat467"
__version__ = "0.0.0"
__license__ = "GNU General Public License Version 3"


from typing import Any, Final

import httpx
import market_api
import trio
from result import Result

import market_server

CATEGORY_ORDER = (
    market_api.PublicationCategory.APPLICATIONS,
    market_api.PublicationCategory.WALLPAPERS,
    market_api.PublicationCategory.SCRIPTS,
    market_api.PublicationCategory.LIBRARIES,
)


async def get_all_publications(
    client: httpx.AsyncClient,
    category_id: market_api.PublicationCategory,
    per_request: int = 100,
    request_delay: float = 0.5,
    request_limiter: trio.CapacityLimiter | None = None,
) -> dict[int, market_api.SearchPublication]:
    """Return a dictionary mapping publication ids to publication objects.

    For `per_request`, see `get_publications`'s `count` argument.

    Returns all results in the entire marketplace for a given category.
    """
    if request_limiter is None:
        request_limiter = trio.CapacityLimiter(1)
    all_items: dict[int, market_api.SearchPublication] = {}
    page = 0

    while True:
        async with request_limiter:
            publications = await market_api.get_publications(
                client,
                category_id=category_id,
                offset=(page * per_request),
                count=per_request,
                order_by="date",
                order_direction="desc",
            )
        print(f"[get_all_publications] response count = {len(publications)}")
        # Slight delay to make server not error/rate-limit
        await trio.sleep(request_delay)

        if not publications:
            break
        for publication in publications:
            all_items[publication.file_id] = publication
        break
        page += 1
        print(f"\n{page = }\n")
    return all_items


PUBLICATION_KEEP: Final = set(market_api.Publication._fields) - {
    "file_id",
    "translated_description",
    "dependencies_data",
    "all_dependencies",
    "average_rating",
}


async def query_publication(
    client: httpx.AsyncClient,
    file_id: int,
    request_limiter: trio.CapacityLimiter | None = None,
    request_delay: float = 0.5,
) -> Result[market_api.Publication]:
    """Return Result, success -> publication, fail -> error text."""
    if request_limiter is None:
        request_limiter = trio.CapacityLimiter(1)
    try:
        async with request_limiter:
            publication = await market_api.get_publication(
                client,
                file_id,
                market_api.PublicationLanguage.ENGLISH,
            )
            await trio.sleep(request_delay)
    except market_api.APIError as exc:
        await trio.sleep(request_delay)
        return Result.fail(exc)
    return Result.ok(publication)


async def save_info(
    client: httpx.AsyncClient,
    publications: dict[str, dict[str, Any]],
    reviews: dict[str, dict[str, Any]],
    file_id: int,
    found: set[int],
    request_limiter: trio.CapacityLimiter | None = None,
    request_delay: float = 0.5,
) -> bool:
    """Save info recursively about publication with file_id and its dependencies."""
    if request_limiter is None:
        request_limiter = trio.CapacityLimiter(1)
    if file_id in found:
        return True
    found.add(file_id)
    publication_result = await query_publication(
        client,
        file_id,
        request_limiter,
        request_delay,
    )
    if not publication_result:
        print(publication_result.value)
        return False
    publication = publication_result.unwrap()

    if publication.file_id != file_id:
        print(
            f"#### ERROR ####\nSearch Publication ID {file_id!r} does not match requested ID {publication.file_id!r}",
        )

    pub: dict[str, object] = publications.get(str(file_id), {})
    if not pub:
        print(
            f"New publication {publication.publication_name!r} by {publication.user_name!r} (id {file_id})",
        )

    # Update publication data
    for k, v in publication._asdict().items():
        if k not in PUBLICATION_KEEP:
            continue
        if k == "downloads" and not v:
            continue
        if v is not None:
            if k in pub and pub[k] != v:
                print(f"{file_id} [{k}] {pub[k]!r} -> {v!r}")
            pub[k] = v
    publications[str(file_id)] = pub

    # Record reviews
    async with request_limiter:
        reviews_response = await market_api.get_reviews(
            client,
            file_id,
            # TODO: Add offset to handle overloads
        )
        await trio.sleep(request_delay)

    if len(reviews) == 100:
        print(f"{file_id = } Likely review overload")

    pub_reviews = reviews.get(str(file_id), {})

    for review in reviews_response:
        review_dict = review._asdict()
        review_dict.update({"votes": review_dict["votes"]._asdict()})
        pub_reviews[str(review.id)] = review_dict

    if pub_reviews:
        reviews[str(file_id)] = pub_reviews

    # Handle dependencies
    if not publication.all_dependencies:
        return True
    for dep_id in publication.all_dependencies:
        query_success = await save_info(
            client,
            publications,
            reviews,
            dep_id,
            found,
            request_limiter,
            request_delay,
        )
        if query_success:
            continue
        # Private dependency

        dep_pub: dict[str, object] = publications.get(str(dep_id), {})

        # Record known data
        for k, v in (
            publication.dependencies_data[int(dep_id)]._asdict().items()
        ):
            if v is None:
                continue
            if k in dep_pub and dep_pub[k] != v:
                print(f"d{dep_id} [{k}] {dep_pub[k]!r} -> {v!r}")
            dep_pub[k] = v

        if (
            dep_pub.get("user_name", publication.user_name)
            != publication.user_name
        ):
            print(
                f"d{dep_id} [user_name] {dep_pub['user_name']!r} -> {publication.user_name!r}",
            )
        dep_pub["user_name"] = publication.user_name
        if (
            dep_pub.get("timestamp", publication.timestamp)
            != publication.timestamp
        ):
            print(
                f"d{dep_id} [timestamp] {dep_pub['timestamp']!r} -> {publication.timestamp!r}",
            )
        dep_pub["timestamp"] = publication.timestamp

        publications[str(dep_id)] = dep_pub
    return True


async def async_run() -> None:
    """Run program."""
    records = market_server.get_records_path()
    request_limiter = trio.CapacityLimiter(8)
    request_delay = 0.5

    found: set[int] = set()
    async with market_server.database.Database(
        records / "publications.json",
    ) as publications:
        # found |= set(map(int, publications))
        async with market_server.database.Database(
            records / "reviews.json",
        ) as reviews:
            async with httpx.AsyncClient() as client:
                statistics = await market_api.get_statistics(client)
                market_api.pretty_print_response(statistics)
                async with trio.open_nursery(
                    strict_exception_groups=True,
                ) as nursery:
                    for category in CATEGORY_ORDER:
                        search_publications = await get_all_publications(
                            client,
                            category,
                            request_delay=request_delay,
                            request_limiter=request_limiter,
                        )
                        print(
                            f"{category = } complete ({len(search_publications)} publications)",
                        )
                        for (
                            pub_id,
                            _search_publication,
                        ) in search_publications.items():
                            nursery.start_soon(
                                save_info,
                                client,
                                publications,
                                reviews,
                                pub_id,
                                found,
                                request_limiter,
                                request_delay,
                                name=pub_id,
                            )
                print("Waiting for publication logging to complete...")
            print("Action complete, saving results...")
    print("Save complete.")

    print(
        f"Found {len(publications)}/{statistics.publications_count} publications.",
    )


def run() -> None:
    """Entry point."""
    trio.run(async_run)


if __name__ == "__main__":
    print(f"{__title__} v{__version__}\nProgrammed by {__author__}.\n")
    run()
