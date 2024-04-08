"""Schema - API Schema."""

# Programmed by CoolCat467

from __future__ import annotations

# Schema - API Schema
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

__title__ = "Schema"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"


import inspect
import math
import time
import traceback
import uuid
from collections import Counter, deque
from email import message_from_string
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.policy import default as email_default_policy
from enum import IntEnum
from secrets import token_urlsafe
from typing import TYPE_CHECKING, Any, Final, NamedTuple, cast

import trio
from httpx import URL, InvalidURL

from market_server import api, database, security

if TYPE_CHECKING:
    from typing_extensions import Self

LICENSES: Final = {
    1: "MIT",
    2: "GNU GPLv3",
    3: "GNU AGPLv3",
    4: "GNU LGPLv3",
    5: "Apache Licence 2.0",
    6: "Mozilla Public License 2.0",
    7: "The Unlicense",
}


class PUBLICATION_CATEGORY(IntEnum):  # noqa: N801
    """Publication category enums."""

    Applications = 1
    Libraries = 2
    Scripts = 3
    Wallpapers = 4


RESERVED_NAMES: Final = {
    "true",
    "false",
    "null",
    # If imported cannot use because vote users not given (see ReviewVotes)
    "total",
    "positive",
    "negative",
}

ALLOWED_EMAIL_PROVIDERS: Final = {
    "gmail.com",
    "icloud.com",
    "yahoo.com",
    "me.com",
    "hotmail.com",
    "live.com",
    "qq.com",
    "outlook.com",
    "googlemail.com",
    "163.com",
    "duck.com",
    "mail.ru",
    "yandex.ru",
    "bk.ru",
    "list.ru",
    "ya.ru",
    "inbox.ru",
    "rambler.ru",
    "spaces.ru",
    "buttex.ru",
    "i.ua",
    "yandex.ua",
    "ukr.net",
    "sevenwolden.org",
    "live.co.uk",
    "live.fr",
    "web.de",
}

PEPPER = "global socks are fuzzy and secure passwords are nice"


class Statistics(NamedTuple):
    """Marketplace Statistics Result Data."""

    users_count: int
    publications_count: int
    reviews_count: int
    messages_count: int
    last_registered_user: str | None
    most_popular_user: str | None


class LoginResponse(NamedTuple):
    """Login Data returned by `login`."""

    id: int
    token: str
    name: str
    email: str
    is_verified: bool
    timestamp: int


class SearchPublication(NamedTuple):
    """Partial Publication data returned from search endpoint."""

    file_id: int
    publication_name: str
    user_name: str
    version: int | float
    category_id: int
    reviews_count: int

    icon_url: str | None = None

    average_rating: float | None = None
    popularity: float | None = None


class Notification(NamedTuple):
    """Notification object from `dialogs` endpoint."""

    dialog_user_name: str
    timestamp: int
    text: str
    last_message_is_read: bool
    last_message_user_name: str
    last_message_user_id: int


class Message(NamedTuple):
    """Message object."""

    text: str
    user_name: str
    timestamp: int


class UploadDependency(NamedTuple):
    """Dependency argument item from Upload/Update Publication."""

    publication_name: str | None
    path: str | None
    source_url: str | None

    @classmethod
    def parse_table_entry(
        cls,
        entry: dict[str, str | object],
    ) -> Self | None:
        """Parse dependency input table entry or return None."""
        publication_name = entry.get("publication_name")
        if not isinstance(publication_name, str):
            publication_name = None
        path = entry.get("path")
        if not isinstance(path, str):
            path = None
        source_url = entry.get("source_url")
        if not isinstance(source_url, str):
            source_url = None

        if not any((publication_name, path, source_url)):
            return None

        return cls(
            publication_name=publication_name,
            path=path,
            source_url=source_url,
        )


class Dependency(NamedTuple):
    """Dependency item from Publication."""

    source_url: str
    path: str
    version: int | float
    publication_name: str | None = None
    category_id: int | None = None


class ReviewVotes(NamedTuple):
    """Review votes data."""

    total: int = 0
    positive: int = 0
    negative: int = 0


class Review(NamedTuple):
    """Review response object from `reviews` endpoint."""

    id: int
    user_name: str
    rating: int
    comment: str
    timestamp: int
    votes: ReviewVotes


class Publication(NamedTuple):
    """Full publication object that the `publication` endpoint gives us."""

    file_id: int
    publication_name: str
    user_name: str
    version: int | float
    category_id: int

    source_url: str
    path: str
    license_id: int
    timestamp: int
    initial_description: str
    translated_description: str
    dependencies_data: dict[int, Dependency]

    dependencies: list[int] | None = None
    all_dependencies: list[int] | None = None

    icon_url: str | None = None

    average_rating: float | None = None
    whats_new: str | None = None
    whats_new_version: float | None = None


def parse_email_address(string: str) -> Address | None:
    """Parse email address from string."""
    try:
        msg = message_from_string(f"To: {string}", policy=email_default_policy)
        to = msg["to"]
    except (IndexError, HeaderParseError):
        return None
    if not to:
        return None
    value = to.addresses[0]
    assert isinstance(value, Address)
    if not value.username or not value.domain:
        return None
    return value


def parse_int(string: str | int) -> int | None:
    """Try to parse int. Return None on failure."""
    try:
        return int(string)
    except ValueError:
        return None


def parse_table(string: str) -> dict[str, Any]:
    """Parse encoded table."""

    def set_key(dict_: dict[str, Any], keys: list[str], value: str) -> None:
        key = keys[0].removesuffix("]")
        if len(keys) == 1:
            dict_[key] = value
            return
        dict_.setdefault(key, {})
        set_key(dict_[key], keys[1:], value)

    root: dict[str, Any] = {}
    for part in string.split("&"):
        if "=" not in part:
            continue
        key_data, value = part.split("=", 1)
        set_key(root, key_data.split("["), value)

    return root


def parse_int_list(string: str) -> list[int]:
    """Parse integer list.

    ex `[0]=27&[1]=49` -> [27, 49]
    ex `[3]=27&[1]=49` -> [49, 27]
    """
    table = parse_table(string)
    result: list[int] = []
    if "" not in table:
        return result
    for key in sorted(table[""].keys()):
        parsed = parse_int(table[""][key])
        if parsed is None:
            continue
        result.append(parsed)
    return result


def send_email(address: str, subject: str, message: str) -> None:
    """Sent email to given address."""
    print(
        f"Wanted to send email to {address!r}:\nSubject: {subject}\n{message}",
    )


class Version_2_04:  # noqa: N801
    """API version 2.04."""

    __slots__ = ("records_root",)

    @property
    def users_path(self) -> trio.Path:
        """User records path."""
        return self.records_root / "users.json"

    @property
    def login_path(self) -> trio.Path:
        """Login token records path."""
        return self.records_root / "login.json"

    @property
    def ids_path(self) -> trio.Path:
        """ID records path."""
        return self.records_root / "ids.json"

    @property
    def publications_path(self) -> trio.Path:
        """Publication records path."""
        return self.records_root / "publications.json"

    @property
    def reviews_path(self) -> trio.Path:
        """Review records path."""
        return self.records_root / "reviews.json"

    def __init__(self, root_path: str | trio.Path) -> None:
        """Initialize records path."""
        self.records_root = trio.Path(root_path) / "records"

    def __repr__(self) -> str:
        """Return representation of self."""
        return f"{self.__class__.__name__}(root_path = {self.records_root.parent!r})"

    def create_login_cookie_data(self, username: str) -> str:
        """Generate UUID associated with a specific user.

        Only one instance of an account should be able
        to log in at any given time, subsequent will invalidate older
        sessions. This will make remembering instances easier
        """
        # Get login database
        logins = database.load(self.login_path)

        # Make new random code until it does not exist
        while (code := str(uuid.uuid4())) in logins:
            continue

        # Delete old tokens
        table = logins.table("token")
        tokens = table["token"]
        delete: list[str] = []
        for index, user in enumerate(table["user"]):
            if user != username:
                continue
            delete.append(tokens[index])
        for token in delete:
            del logins[token]

        # Make logins expire after a while
        expires = int(time.time()) + 2628000  # Good for 1 month

        # Write data back
        logins[code] = {
            "user": username,
            "expires": expires,
        }
        logins.write_file()
        return code

    def get_login_from_cookie_data(self, code: str) -> str | None:
        """Get username from cookie data.

        If cookie data is invalid return None
        """
        # Get login database
        logins = database.load(self.login_path)

        # Attempt to get entry for code. Using get instead of
        # "in" search and then index means is faster
        entry = logins.get(code, None)
        # If not exists or malformed entry, is bad
        if entry is None or not isinstance(entry, dict):
            return None
        # If expires not exist in entry or time expired, is bad and delete entry
        if entry.get("expires", 0) < int(time.time()):
            del logins[code]
            logins.write_file()
            return None
        # Otherwise attempt to return username field or is bad because malformed
        value = entry.get("user", None)
        assert isinstance(value, str) or value is None
        return value

    def get_total_reviews_count(self) -> int:
        """Return the total number of reviews."""
        review_records = database.load(self.reviews_path)
        review_count = 0
        for reviews in review_records.values():
            review_count += len(reviews)
        return review_count

    async def cmd_statistics(self) -> str:
        """Return server statistics data."""
        await trio.lowlevel.checkpoint()
        users = database.load(self.users_path)
        publications = database.load(self.publications_path)

        table = users.table("name")
        last: str | None = None
        if table["name"]:
            last = table["name"][-1]

        review_count = self.get_total_reviews_count()

        stats = Statistics(
            len(users),
            len(publications),
            review_count,
            0,
            last,
            None,
        )
        return api.success_schema(stats)

    async def cmd_register(
        self,
        name: str,
        email: str,
        password: str,
    ) -> api.Response:
        """Change password given email, current password, and new password."""
        await trio.lowlevel.checkpoint()

        if name in RESERVED_NAMES:
            return api.failure(f"Name {name!r} is reserved")

        users = database.load(self.users_path)

        if name in users:
            return api.failure(
                f"User with specified name ({name}) is already registered",
            )

        address = Address() if not email else parse_email_address(email)

        if address is None:
            return api.failure(
                "Invalid email address",
            )

        if address.domain not in ALLOWED_EMAIL_PROVIDERS:
            allowed = ", ".join(ALLOWED_EMAIL_PROVIDERS)
            return api.failure(
                f"Specified e-mail provider is not supported. Use one of these: {allowed}",
            )

        parsed_email = f"{address.username}@{address.domain}"

        if parsed_email in users.table("name")["email"]:
            return api.failure(
                f"User with specified email ({email}) is already registered",
            )

        users[name] = {
            "email": parsed_email,
            "is_verified": False,
            "password": security.create_new_login_credentials(
                password,
                PEPPER,
            ),
            "timestamp": math.floor(time.time()),
            "verify_token": token_urlsafe(37),
        }
        users.write_file()

        send_email(
            parsed_email,
            "Submit MineOS account registration",
            f"""Hello, friend.


Thank you for your interest in our software products. We believe that everyone
can make an invaluable contribution to their development by publishing awesome
applications and evaluating existing ones.


Follow this link to verify your MineOS account:
http://<server_url>/MineOSAPI/2.04/verify.php?token={users[name]['verify_token']}


Here is your registration data:
Username: {name}
Password: {password}


Sincerely yours,
Timofeev Igor
MineOS Dev Team""",
        )
        return api.success_direct(
            f"Check your e-mail ({email}) and spam folder message to submit your MineOS account",
        )

    def verify(
        self,
        verify_token: str,
    ) -> bool:
        """Return if successful verifying user."""
        users = database.load(self.users_path)

        table = users.table("name")
        id_ = table.get_id("verify_token", verify_token)
        if id_ is None:
            return False

        username = table["name"][id_]
        if username is None:
            return False
        users[username].update(
            {
                "is_verified": True,
                "verify_token": None,
            },
        )
        users.write_file()

        return True

    async def cmd_login(
        self,
        email: str | None,
        name: str | None,
        password: str,
    ) -> api.Response:
        """Login given email or username, and password."""
        await trio.lowlevel.checkpoint()
        if email is None and name is None:
            return api.failure("Missing arguments: email or name, password")
        users = database.load(self.users_path)
        table = users.table("name")
        if name is None:
            id_ = table.get_id("email", email)
            if id_ is not None:
                name = table["name"][id_]
        else:
            id_ = table.get_id("name", name)
        if name is None or id_ is None:
            return api.failure("Invalid (name or email) or password")
        user = users.get(name)
        if user is None:
            return api.failure("Invalid (name or email) or password")
        success = await security.compare_hash(
            password,
            user["password"],
            PEPPER,
        )
        if not success:
            return api.failure("Invalid (name or email) or password")
        if not user["is_verified"]:
            return api.failure(
                f"Check your e-mail ({user['email']}) and spam folder for message to verify your account",
            )
        token = self.create_login_cookie_data(name)
        return api.success_schema(
            LoginResponse(
                id=id_,
                token=token,
                name=name,
                **{k: user[k] for k in ("email", "is_verified", "timestamp")},
            ),
        )

    async def cmd_change_password(
        self,
        email: str,
        current_password: str,
        new_password: str,
    ) -> api.Response:
        """Change password given email, current password, and new password."""
        await trio.lowlevel.checkpoint()
        users = database.load(self.users_path)
        table = users.table("name")
        id_ = table.get_id("email", email)
        name: str | None = None
        if id_ is not None:
            name = table["name"][id_]

        if name is None:
            return api.failure("Invalid current password")

        user = users.get(name)
        if user is None:
            return api.failure("Invalid current password")

        success = await security.compare_hash(
            current_password,
            user["password"],
            PEPPER,
        )
        if not success:
            return api.failure("Invalid current password")

        users[name].update(
            {
                "password": security.create_new_login_credentials(
                    new_password,
                    PEPPER,
                ),
            },
        )
        users.write_file()

        return api.success()

    def get_dependency(
        self,
        file_id: str | int,
    ) -> tuple[Dependency | None, dict[str, Any]]:
        """Return (Dependency object from file id, publication record) or (None, None) if not found."""
        pub_records = database.load(self.publications_path)
        pub = pub_records.get(str(file_id))
        if pub is None:
            return None, {}
        return (
            Dependency(
                pub["source_url"],
                pub["path"],
                pub["version"],
                pub.get("publication_name"),
                pub.get("category_id"),
            ),
            pub,
        )

    async def cmd_review(
        self,
        token: str,
        file_id: str,
        rating: str,
        comment: str,
    ) -> api.Response:
        """Add a review for a given publication."""
        await trio.lowlevel.checkpoint()
        username = self.get_login_from_cookie_data(token)
        if username is None:
            return api.failure("Token is invalid or expired")

        rating_value = parse_int(rating)
        if rating_value is None or rating_value < 1 or rating_value > 5:
            return api.failure(
                "Rating should be in range of 1 to 5 inclusive",
            )

        review_length = len(comment)
        if review_length < 2 or review_length > 1000:
            return api.failure(
                "Comment length too small/big. Minimum 2 Maximum 1000.",
            )

        pub_records = database.load(self.publications_path)

        publication = pub_records.get(str(file_id))
        if publication is None:
            return api.failure(
                f"Publication with specified file ID ({file_id}) doesn't exist",
            )

        if publication["user_name"] == username:
            return api.failure(
                "Cannot leave a review for a publication you created",
            )

        review_records = database.load(self.reviews_path)

        reviews = review_records.get(file_id, {})

        # Remove previous reviews, otherwise users would be able
        # to manipulate global average by spamming.
        delete_ids: list[str] = []
        for review_id, review in reviews.items():
            if review["user_name"] == username:
                delete_ids.append(str(review_id))
        for delete_id in delete_ids:
            del reviews[delete_id]

        # Get ID for new review
        id_records = database.load(self.ids_path)
        new_review_id = id_records.get("review", None)
        if new_review_id is None:
            new_review_id = -1
            for _file_id, review_data in review_records.items():
                for key in map(int, review_data.keys()):
                    if key > new_review_id:
                        new_review_id = key
            new_review_id += 1
        id_records["review"] = new_review_id + 1
        id_records.write_file()

        # Add new review
        reviews[str(new_review_id)] = {
            "user_name": username,
            "rating": rating_value,
            "comment": comment,
            "timestamp": math.floor(time.time()),
            "votes": {},
        }

        # Save changes
        review_records[file_id] = reviews
        review_records.write_file()

        return api.success()

    def review_id_to_file_id(
        self,
        review_id: int,
    ) -> str | None:
        """Return file_id where given review_id is located or None."""
        review_records = database.load(self.reviews_path)
        search = str(review_id)
        for file_id, reviews in review_records.items():
            if search in reviews:
                return file_id
        return None

    async def cmd_review_vote(
        self,
        token: str,
        review_id: str,
        helpful: str,
    ) -> api.Response:
        """Vote if a review is helpful or not."""
        await trio.lowlevel.checkpoint()
        review_id_int = parse_int(review_id)
        if review_id_int is None:
            return api.failure("`review_id` is invalid")

        helpful_int = parse_int(helpful)
        if helpful_int is None or helpful_int not in (0, 1):
            return api.failure("`helpful` is invalid, either 0 or 1")

        username = self.get_login_from_cookie_data(token)
        if username is None:
            return api.failure("Token is invalid or expired")

        review_records = database.load(self.reviews_path)
        file_id = self.review_id_to_file_id(review_id_int)
        if file_id is None:
            return api.failure(
                f"Review with specified file ID ({review_id}) doesn't exist",
            )

        if (
            review_records[file_id][str(review_id_int)]["user_name"]
            == username
        ):
            return api.failure(
                "Cannot vote on a comment you made",
            )

        review_records[file_id][str(review_id_int)]["votes"][username] = bool(
            helpful_int,
        )
        review_records.write_file()
        return api.success()

    async def cmd_reviews(
        self,
        file_id: str,
        offset: str | None,
        count: str | None,
    ) -> api.Response:
        """Get reviews for given file id."""
        await trio.lowlevel.checkpoint()
        offset_int = parse_int(offset or 0)
        if offset_int is None or offset_int < 0:
            return api.failure("Invalid offset")

        review_records = database.load(self.reviews_path)

        reviews = review_records.get(file_id)
        if not reviews or offset_int > len(reviews):
            return api.success_direct([])

        count_int = parse_int(count or len(reviews))
        if count_int is None or count_int < 1:
            return api.failure("Invalid count")
        count_int = min(count_int, len(reviews))

        keys = sorted(reviews)[offset_int:count_int]
        review_data: list[Review] = []
        for review_id in keys:
            review = reviews[review_id]
            # Deep copy because deletes
            votes = dict(review["votes"].items())

            # Handle imported data
            if "total" in votes:
                del votes["total"]
            add_positive = 0
            if "positive" in votes:
                add_positive = votes["positive"]
                del votes["positive"]
            add_negative = 0
            if "negative" in votes:
                add_negative = votes["negative"]
                del votes["negative"]

            vote_data = Counter(votes.values())
            vote_data[True] += add_positive
            vote_data[False] += add_negative

            votes = ReviewVotes(
                total=sum(vote_data.values()),
                positive=vote_data[True],
                negative=vote_data[False],
            )
            review_data.append(
                Review(
                    **{
                        k: review[k]
                        for k in ("rating", "comment", "timestamp")
                    },
                    user_name=review["user_name"],
                    id=review_id,
                    votes=votes,
                ),
            )

        return api.success_direct(review_data)

    def get_average_rating(
        self,
        file_id: str | int,
    ) -> float | None:
        """Return average rating for given publication."""
        review_records = database.load(self.reviews_path)
        reviews = review_records.get(str(file_id))
        if not reviews:
            return None
        table = database.Table(reviews, "review_id")
        ratings = table["rating"]
        return sum(map(int, ratings)) / len(ratings)

    def get_publication(
        self,
        file_id: str | int,
        language_id: int,
    ) -> Publication | str:
        """Return Publication object from file id or error text if not found."""
        pub_records = database.load(self.publications_path)
        pub = pub_records.get(str(file_id))
        if pub is None:
            return (
                f"Publication with specified file ID ({file_id}) doesn't exist"
            )
        write = (
            "publication_name",
            "user_name",
            "version",
            "category_id",
            "source_url",
            "path",
            "license_id",
            "timestamp",
            "initial_description",
            "dependencies",
            "icon_url",
            "whats_new",
            "whats_new_version",
        )
        # TODO: Languages
        translated_description: str = pub["initial_description"]

        all_dependencies_set: set[int] = set()
        dependencies_data: dict[int, Dependency] = {}
        if pub["dependencies"]:
            toplevel_deps: deque[int] = deque(pub["dependencies"])

            while toplevel_deps:
                dep_file_id = toplevel_deps.popleft()
                if dep_file_id in all_dependencies_set:
                    continue
                all_dependencies_set.add(dep_file_id)
                dependency, dep_pub = self.get_dependency(dep_file_id)
                if dependency is None:
                    ##print(
                    ##    f"Publication with specified file ID ({dep_file_id}) doesn't exist",
                    ##)
                    continue
                dependencies_data[dep_file_id] = dependency
                if sub_deps := dep_pub.get("dependencies"):
                    toplevel_deps.extend(sub_deps)

        all_dependencies = sorted(all_dependencies_set)
        dependencies_data = {
            k: dependencies_data[k] for k in sorted(dependencies_data)
        }

        average_rating = self.get_average_rating(file_id)

        return Publication(
            **{k: pub[k] for k in write},
            file_id=int(file_id),
            translated_description=translated_description,
            all_dependencies=all_dependencies,
            dependencies_data=dependencies_data,
            average_rating=average_rating,
        )

    async def cmd_publication(
        self,
        file_id: str,
        language_id: str,
    ) -> api.Response:
        """Return publication details."""
        await trio.lowlevel.checkpoint()
        pub_records = database.load(self.publications_path)
        pub = pub_records.get(file_id)
        if pub is None:
            return api.failure(
                f"Publication with specified file ID ({file_id}) doesn't exist",
            )
        lang_id = parse_int(language_id)
        if lang_id is None:
            return api.failure(
                f"Language with specified ID ({language_id}) isn't supported",
            )

        publication_or_error = self.get_publication(file_id, lang_id)

        if isinstance(publication_or_error, str):
            return api.failure(publication_or_error)
        return api.success_schema(publication_or_error)

    def get_review_count(
        self,
        file_id: str | int,
    ) -> int | None:
        """Return ReviewVotes or None if file id doesn't exist."""
        review_records = database.load(self.reviews_path)
        reviews = review_records.get(str(file_id))
        if not reviews:
            return None
        return len(reviews)

    def get_publication_popularity(
        self,
        file_id: str | int,
    ) -> float:
        """Return `popularity` value for given publication."""
        average_rating = self.get_average_rating(file_id) or 5
        review_count = self.get_review_count(file_id) or 0
        count_id = max(1, self.get_total_reviews_count())
        return (review_count * average_rating) / count_id

    async def cmd_publications(
        self,
        category_id: str,
        order_by: str | None,
        order_direction: str | None,
        offset: str | None,
        count: str | None,
        search: str | None,
        file_ids: str | None,
    ) -> api.Response:
        """Search for a publication."""
        await trio.lowlevel.checkpoint()
        category = parse_int(category_id)
        if category is None or category < 0:
            return api.failure("Invalid category")

        if order_by not in {"popularity", "rating", "name", "date", None}:
            return api.failure(
                "Invalid order by, valid is popularity, rating, name, or date.",
            )
        if order_by is None:
            order_by = "date"

        descending = order_direction != "asc"

        offset_value = parse_int(offset or 0)
        if offset_value is None:
            return api.failure("Invalid offset")

        count_value: int | None = None
        if count is not None:
            count_value = parse_int(count)
        if count_value is not None and count_value < 1:
            return api.failure("count is less than one")

        get_files: list[int] | None = None
        if file_ids is not None:
            get_files = parse_int_list(file_ids) or None

        pub_records = database.load(self.publications_path)
        table = pub_records.table("file_id")

        # Get record ids of files that match
        category_records: dict[str, dict[str, str]] = {}
        pub_file_ids = table["file_id"]
        for index, cat_id in enumerate(table["category_id"]):
            if cat_id == category:
                file_id = pub_file_ids[index]
                category_records[file_id] = pub_records[file_id]

        obtain_files: set[str] = set(category_records.keys())
        if get_files is not None:
            obtain_files &= set(map(str, get_files))

        if search:
            obtain_files = {
                fid
                for fid in obtain_files
                if search in pub_records.get(fid, {}).get("publication_name")
            }

        if order_by == "popularity":
            match_ids = sorted(
                obtain_files,
                key=self.get_publication_popularity,
                reverse=descending,
            )
        elif order_by == "rating":
            match_ids = sorted(
                obtain_files,
                key=lambda f: self.get_average_rating(f) or 0,
                reverse=descending,
            )
        elif order_by == "name":
            match_ids = sorted(
                obtain_files,
                key=lambda f: category_records[f]["publication_name"],
                reverse=descending,
            )
        else:
            match_ids = sorted(
                obtain_files,
                key=lambda f: category_records[f]["timestamp"],
                reverse=descending,
            )

        if count_value is None:
            count_value = len(match_ids)

        offset_value = max(0, min(len(match_ids) - 1, offset_value))
        count_value = max(len(match_ids), min(0, count_value))

        matches: list[SearchPublication] = []
        for file_id in match_ids[offset_value:count_value]:
            publication = pub_records.get(file_id)
            if publication is None:
                continue
            matches.append(
                SearchPublication(
                    int(file_id),
                    **{
                        k: publication.get(k)
                        for k in (
                            "publication_name",
                            "user_name",
                            "version",
                            "category_id",
                            "icon_url",
                        )
                    },
                    reviews_count=self.get_review_count(file_id) or 0,
                    average_rating=self.get_average_rating(file_id),
                    popularity=self.get_publication_popularity(file_id),
                ),
            )

        return api.success_direct(matches, True)

    async def cmd_update(
        self,
        token: str,
        file_id: str,
        name: str,
        source_url: str,
        path: str,
        description: str,
        category_id: str,
        dependencies: str,
        license_id: str,
    ) -> api.Response:
        """Handle updating a publication."""
        await trio.lowlevel.checkpoint()
        return await self.publication_edit(
            token=token,
            name=name,
            source_url=source_url,
            path=path,
            description=description,
            category_id=category_id,
            raw_dependencies=dependencies,
            license_id=license_id,
            new=False,
            raw_file_id=file_id,
        )

    async def cmd_upload(
        self,
        token: str,
        name: str,
        source_url: str,
        path: str,
        description: str,
        category_id: str,
        dependencies: str,
        license_id: str,
    ) -> api.Response:
        """Handle uploading a new publication."""
        await trio.lowlevel.checkpoint()
        return await self.publication_edit(
            token=token,
            name=name,
            source_url=source_url,
            path=path,
            description=description,
            category_id=category_id,
            raw_dependencies=dependencies,
            license_id=license_id,
            new=True,
            raw_file_id=None,
        )

    async def publication_edit(
        self,
        token: str,
        name: str,
        source_url: str,
        path: str,
        description: str,
        category_id: str,
        raw_dependencies: str,
        license_id: str,
        new: bool = True,
        raw_file_id: str | None = None,
    ) -> api.Response:
        """Handle uploading or updating a publication."""
        await trio.lowlevel.checkpoint()

        if not new and raw_file_id is None:
            raise RuntimeError("If not new, raw_file_id should be valid!")

        username = self.get_login_from_cookie_data(token)
        if username is None:
            return api.failure("Token is invalid or expired")

        if len(name) > 32:
            return api.failure("Name is too long (max 32 characters)")
        if len(name) < 2:
            return api.failure("Name is too short (min 2 characters)")

        if len(description) < 2:
            return api.failure("Description is too short")
        if len(description) > 1024:
            return api.failure("Description is too long")

        category = parse_int(category_id)
        if category is None or category not in PUBLICATION_CATEGORY:
            return api.failure("Invalid category_id (must be in domain [1,4])")

        if (
            category
            in {
                PUBLICATION_CATEGORY.Applications,
                PUBLICATION_CATEGORY.Wallpapers,
            }
            and path != "Main.lua"
        ):
            return api.failure(
                "Path must be `Main.lua` for Applications and Wallpapers categories.",
            )
        if len(path) < 2:
            return api.failure("Path is too small.")

        license_ = parse_int(license_id)
        if license_ not in LICENSES:
            return api.failure("license_id is invalid")

        try:
            url = URL(source_url)
        except InvalidURL as exc:
            error = exc.args[0]
            return api.failure(f"Invalid source_url ({error})")

        if url.scheme not in {"http", "https"}:
            return api.failure(
                "Invalid source_url (scheme must be http or https)",
            )

        if len(url.host) > 253:
            return api.failure(
                "Invalid source_url (full domain name max size is 253 characters)",
            )

        if "." not in url.host:
            return api.failure("Invalid source_url (must have domain suffix)")
        temp_domain_parts = url.host.split(".")
        if not all(temp_domain_parts):
            return api.failure("Invalid source_url (invalid domain label(s))")
        if not all(len(p) < 64 for p in temp_domain_parts):
            return api.failure("Invalid source_url (invalid domain label(s))")

        src_url = url.copy_with()

        icon_url: str | None = None

        parsed_dependencies_table = parse_table(raw_dependencies).get("", {})
        print(f"{parsed_dependencies_table = }")
        dependencies_data: list[UploadDependency] = []
        for _entry_id, entry_data in parsed_dependencies_table.items():
            parsed_entry = UploadDependency.parse_table_entry(entry_data)
            if not parsed_entry:
                continue
            if parsed_entry.path == "Icon.pic":
                icon_url = parsed_entry.source_url
            dependencies_data.append(parsed_entry)
        print(f"{dependencies_data = }")

        publications = database.load(self.publications_path)
        table = publications.table("file_id")

        exists_id = table.get_id("publication_name", name)
        exists_file_id: str | None = None
        if exists_id is not None:
            exists_file_id = table["file_id"][exists_id]
        if exists_file_id is not None and exists_file_id != raw_file_id:
            return api.failure(
                f"Publication with name {name!r} already exists!",
            )

        if new:
            # Get ID for new publication
            id_records = database.load(self.ids_path)
            new_publication_id = id_records.get("publication", None)
            if new_publication_id is None:
                new_publication_id = max(map(int, publications.keys()))
            id_records["publication"] = new_publication_id + 1
            id_records.write_file()

            file_id = new_publication_id
        else:
            file_id = parse_int(raw_file_id)
            if file_id is None:
                return api.failure("file_id is invalid")
            existing_publication = publications.get(str(file_id))
            if existing_publication is None:
                return api.failure(
                    f"Publication with id {file_id} doesn't exist!",
                )
            if existing_publication["user_name"] != username:
                return api.failure(f"You don't own publication {file_id}!")

        publication = publications.get(str(file_id), {})
        print(f"{publication = }")
        # dependencies_data

        version = 1.00
        dependency_file_ids: list[int] = []

        ##        publication.update(
        publication = {
            "publication_name": name,
            "user_name": username,
            "version": version,
            "category_id": category,
            "source_url": str(src_url),
            "path": path,
            "license_id": license_,
            "timestamp": math.floor(time.time()),
            "initial_description": description,
            "dependencies": dependency_file_ids or None,
            "icon_url": icon_url,
            "whats_new": None,
            "whats_new_version": None,
        }
        ##        )

        raise NotImplementedError

    def index(self) -> list[str]:
        """Return list of valid scripts."""
        return [a[4:] for a in dir(self) if a.startswith("cmd_")]

    async def script(self, script: str, data: dict[str, str]) -> api.Response:
        """Handle script given post data."""
        await trio.lowlevel.checkpoint()
        attribute = f"cmd_{script}"
        if not hasattr(self, attribute):
            return api.failure("Script not found", 404)

        function = getattr(self, attribute)

        arg_spec = inspect.getfullargspec(function)
        argument_names = arg_spec.args[1:]
        if not argument_names:
            try:
                return cast(api.Response, await function())
            except Exception as exc:
                traceback.print_exception(exc)
                return api.failure("Internal server error", 500)

        send_arguments: dict[str, str | None] = {}
        missing = False
        arguments: list[tuple[bool, str]] = []
        for name in argument_names:
            annotation = arg_spec.annotations[name]

            required = True
            if "None" in annotation:
                required = False
                arguments.append((required, name))

            if name in data:
                send_arguments[name] = data[name]
            elif required:
                missing = True
                arguments.append((required, name))
            else:
                send_arguments[name] = None

        if missing:
            groups: list[list[bool | str]] = []
            last_required = True
            for required, name in arguments:
                if last_required != required or not groups:
                    groups.append([required, name])
                else:  # last == current and not empty
                    groups[-1].append(name)
                last_required = required
            argument_results: list[str] = []
            for idx, group in enumerate(groups):
                assert isinstance(group[0], bool)
                required = bool(group[0])
                arg_names = cast(list[str], group[1:])
                if not required and idx == 0:
                    result = " or ".join(arg_names)
                elif required:
                    result = ", ".join(arg_names)
                else:
                    result = ", ".join(f"[{v}]" for v in arg_names)
                argument_results.append(result)
            arguments_text = ", ".join(argument_results)
            return api.failure(f"Missing arguments: {arguments_text}")
        try:
            return cast(api.Response, await function(**send_arguments))
        except Exception as exc:
            traceback.print_exception(exc)
            return api.failure("Internal server error", 500)


async def run() -> None:
    """Run test of server."""
    server = Version_2_04(await trio.Path(__file__).parent.absolute())
    print(f"{server = }")

    original = {
        "verify",
        "delete",
        "change_password",
        "review",
        "update",
        "upload",
        "dialogs",
        "message",
        "messages",
        "review_vote",
        "publication",
        "statistics",
        "reviews",
        "login",
        "register",
        "publications",
    }
    handled = set(server.index()) | {"verify"}
    unhandled = sorted(original - handled)
    print(f"{unhandled = }")

    ##    print(
    ##        await server.script(
    ##            "register",
    ##            {
    ##                "email": "jerald@gmail.com",
    ##                "name": "jerald",
    ##                "password": "jerald",
    ##            },
    ##        ),
    ##    )
    ##
    try:
        import market_api

        def pprint(value: api.Response) -> None:
            if isinstance(value, str):
                text = value
            else:
                text, _error_code = value
            market_api.pretty_print_response(
                market_api.lua_parser.parse_lua_table(text),
            )

    except ImportError:

        def pprint(value: api.Response) -> None:
            print(value)

    ##    pprint(
    ##        await server.script(
    ##            "upload",
    ##            {
    ##                "token": "26e140ab-4bfa-46d2-a9ce-cc8024b8e48e",
    ##                "name": "test_publication",
    ##                "source_url": "http://example.com",
    ##                "path": "Main.lua",
    ##                "description": "This is a test publication to make sure it works.",
    ##                "category_id": "1",
    ##                "dependencies": "[0][source_url]=https://example.com&[0][path]=Icon.pic",
    ##                "license_id": "2",
    ##            }
    ##        )
    ##    )
    ##    pprint(
    ##        await server.script(
    ##            "update",
    ##            {
    ##                "token": "ecs",
    ##                "file_id": "103",
    ##                "name": "JSON",
    ##                "source_url": "https://raw.githubusercontent.com/IgorTimofeev/MineOS/master/Libraries/JSON.lua",
    ##                "path": "Main.lua",
    ##                "dependencies": "{}",
    ##                "description": "This library allows you to encode/decode Lua tables to/from string JSON result. Mostly used in web applications.",
    ##                "category_id": "2",
    ##                "license_id": "1",
    ##            },
    ##        ),
    ##    )
    ##    pprint(
    ##        await server.script(
    ##            "statistics",
    ##            {},
    ##        ),
    ##    )
    ##    pprint(
    ##        await server.script(
    ##            "publications",
    ##            {
    ##                "category_id": "2",
    ##                "search": "JSON",
    ####                "order_direction": "asc",
    ##            },
    ##        ),
    ##    )
    pprint(
        await server.script(
            "publication",
            {
                "file_id": "1045",  # 1936, 73, 103, 1045
                "language_id": "1",
            },
        ),
    )


##    pprint(
##        await server.script(
##            "login",
##            {"name": "test", "password": "test"},
##        ),
##    )
##    pprint(
##        await server.script(
##            "review",
##            {
##                "token": token,
##                "file_id": "1936",
##                "comment": "This is a comment text",
##                "rating": 5,
##            }
##        )
##    )
##    pprint(
##        await server.script(
##            "review",
##            {
##                "token": "26e140ab-4bfa-46d2-a9ce-cc8024b8e48e",
##                "file_id": "73",
##                "comment": "This is a comment text",
##                "rating": 5,
##            }
##        )
##    )
##    pprint(
##        await server.script(
##            "reviews",
##            {
##                "file_id": "73", # 1936, 73, 103
##            }
##        )
##    )
##    pprint(
##        await server.script(
##            "review_vote",
##            {
##                "token": token,
##                "review_id": "1",
##                "helpful": "1",
##            }
##        )
##    )
##    pprint(
##        await server.script(
##            "reviews",
##            {
##                "file_id": "73",
##            }
##        )
##    )


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    trio.run(run)
