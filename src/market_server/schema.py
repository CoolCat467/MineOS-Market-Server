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
from email.headerregistry import Address
from email.policy import default as email_default_policy
from secrets import token_urlsafe
from typing import Any, Final, NamedTuple, cast

import trio

from market_server import api, database, security

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

    icon_url: str = ""

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
    msg = message_from_string(f"To: {string}", policy=email_default_policy)
    if not msg["to"]:
        return None
    value = msg["to"].addresses[0]
    assert isinstance(value, Address)
    return value


def parse_int(string: str | int) -> int | None:
    """Try to parse int. Return None on failure."""
    try:
        return int(string)
    except ValueError:
        return None


def send_email(address: str, subject: str, message: str) -> None:
    """Sent email to given address."""
    print(
        f"Wanted to send email to {address!r}:\nSubject: {subject}\n{message}",
    )


class Version_2_04:  # noqa: N801
    """API version 2.04."""

    __slots__ = ()

    records_root = trio.Path("records")

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

    ##    def __init__(self, users: database.Records) -> None:
    ##        self.users = users

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

    async def cmd_statistics(self) -> str:
        """Return server statistics data."""
        await trio.lowlevel.checkpoint()
        users = database.load(self.users_path)
        publications = database.load(self.publications_path)
        review_records = database.load(self.reviews_path)

        table = users.table("name")
        last: str | None = None
        if table["name"]:
            last = table["name"][-1]

        review_count = 0
        for reviews in review_records.values():
            review_count += len(reviews)

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

        pub_records = database.load(self.publications_path)

        publication = pub_records.get(str(file_id))
        if publication is None:
            return api.failure(
                f"Publication with specified file ID ({file_id}) doesn't exist",
            )

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

        review_records = database.load(self.reviews_path)

        reviews = review_records.get(file_id, {})

        # Remove previous reviews, otherwise users would be able
        # to manipulate global average by spamming.
        delete_ids: list[str] = []
        for review_id, review in reviews.items():
            if review["username"] == username:
                delete_ids.append(str(review_id))
        for delete_id in delete_ids:
            del reviews[delete_id]

        # Get ID for new review
        id_records = database.load(self.ids_path)
        new_review_id = id_records.get("review", 0)
        id_records["review"] = new_review_id + 1
        id_records.write_file()

        # Add new review
        reviews[str(new_review_id)] = {
            "username": username,
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
            vote_data = Counter(review["votes"].values())
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
                    user_name=review["username"],
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
        # TODO: Languages
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
        category = parse_int(category_id)
        if category is None or category < 0:
            return api.failure("Invalid category")
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
    server = Version_2_04()

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
    import market_api

    def pprint(value: api.Response) -> None:
        if isinstance(value, str):
            text = value
        else:
            text, _error_code = value
        market_api.pretty_print_response(
            market_api.lua_parser.parse_lua_table(text),  # type: ignore[arg-type]
        )

    ##
    ##    print(
    ##        await server.script(
    ##            "statistics",
    ##            {},
    ##        ),
    ##    )
    pprint(
        await server.script(
            "publications",
            {},
        ),
    )
    ##    pprint(
    ##        await server.script(
    ##            "publication",
    ##            {
    ##                "file_id": "73",  # 1936, 73
    ##                "language_id": "1",
    ##            },
    ##        ),
    ##    )
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
    ##                "token": token,
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
    ##                "file_id": "73", # 1936
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
