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
import uuid
from email import message_from_string
from email.headerregistry import Address
from email.policy import default as email_default_policy
from secrets import token_urlsafe
from typing import Final, NamedTuple

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
    last_registered_user: str
    most_popular_user: str


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

    average_rating: float = 0
    whats_new: str | None = None
    whats_new_version: float | None = None


def parse_email_address(string: str) -> Address:
    """Parse email address from string."""
    msg = message_from_string(f"To: {string}", policy=email_default_policy)
    if not msg["to"]:
        return None
    return msg["to"].addresses[0]


def send_email(address: str, subject: str, message: str) -> None:
    """Sent email to given address."""
    print(
        f"Wanted to send email to {address!r}:\nSubject: {subject}\n{message}",
    )


class Version_2_04:  # noqa: N801
    """API version 2.04."""

    __slots__ = ()

    users_path = trio.Path("records") / "users.json"
    login_path = trio.Path("records") / "login.json"

    ##    def __init__(self, users: database.Records) -> None:
    ##        self.users = users

    @classmethod
    def create_login_cookie_data(cls, username: str) -> str:
        """Generate UUID associated with a specific user.

        Only one instance of an account should be able
        to log in at any given time, subsequent will invalidate older
        sessions. This will make remembering instances easier
        """
        # Get login database
        logins = database.load(cls.login_path)

        # Make new random code until it does not exist
        while (code := str(uuid.uuid4())) in logins:
            continue

        # Make logins expire after a while
        expires = int(time.time()) + 2628000  # Good for 1 month

        # Write data back
        logins[code] = {
            "user": username,
            "expires": expires,
        }
        logins.write_file()
        return code

    @classmethod
    def get_login_from_cookie_data(cls, code: str) -> str | None:
        """Get username from cookie data.

        If cookie data is invalid return None
        """
        # Get login database
        logins = database.load(cls.login_path)

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
        table = users.table("name")
        last: str | None = None
        if table["name"]:
            last = table["name"][-1]
        stats = Statistics(len(users), 0, 0, 0, last, "")
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

        ##        return api.failure("Invalid current password", 401)
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
        if name is None:
            return api.failure("Invalid current password")
        user = users.get(name)
        if user is None:
            return api.failure("Invalid current password")
        if not user["is_verified"]:
            return api.failure("User is not verified")
        success = await security.compare_hash(
            password,
            user["password"],
            PEPPER,
        )
        if not success:
            return api.failure("Invalid current password")
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
            api.failure("Invalid current password")

        user = users.get(name)
        if user is None:
            return api.failure("Invalid current password")

        if not user["is_verified"]:
            return api.failure("User is not verified")

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

        return api.success_direct("Updated password")

    ##    def cmd_publication(self, file_id: str, language_id: str) -> api.Response:
    ##        """Return publication details."""
    ##        return api.success_schema(Publication)

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
            return await function()

        send_arguments: dict[str, str] = {}
        missing = False
        arguments_or: list[list[str]] = []
        for name in argument_names:
            annotation = arg_spec.annotations[name]

            required = True
            if "None" in annotation:
                required = False
                if not arguments_or:
                    arguments_or.append([])
                arguments_or[-1].append(name)
            else:
                arguments_or.append([name])

            if name in data:
                send_arguments[name] = data[name]
            elif required:
                missing = True
            else:
                send_arguments[name] = None

        if missing:
            arguments_text = ", ".join(
                " or ".join(group) for group in arguments_or
            )
            return api.failure(f"Missing arguments: {arguments_text}")
        return await function(**send_arguments)


async def run() -> None:
    """Run test of server."""
    server = Version_2_04()
    print(
        await server.script(
            "register",
            {
                "email": "jerald@gmail.com",
                "name": "jerald",
                "password": "jerald",
            },
        ),
    )


##    print(
##        await server.script(
##            "login",
##            {"name": "test", "password": "test"},
##        ),
##    )
##    print(
##        await server.script(
##            "login",
##            {"email": "test@gmail.com", "password": "test"},
##        ),
##    )
##    print(
##        await server.script(
##            "change_password",
##            {"email": "test@gmail.com", "current_password": "test2", "new_password": "test"},
##        ),
##    )
##    print(await server.script("statistics", {}))


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    trio.run(run)
