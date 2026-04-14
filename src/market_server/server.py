"""Market Server - MineOS App Market Server.

Copyright (C) 2024-2026  CoolCat467

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations

__title__ = "MineOS Market Webserver"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"
__version__ = "1.0.3"


import argparse
import sys
import time
from collections import ChainMap
from collections.abc import AsyncIterator, Iterable
from os import getenv, makedirs, path
from typing import TYPE_CHECKING, Any, Final, TypeVar, cast

import trio
from hypercorn.config import Config
from hypercorn.trio import serve
from quart import request
from quart.templating import stream_template
from quart_trio import QuartTrio

from market_server import api, backups, database, htmlgen, schema
from market_server.server_utils import find_ip, pretty_exception

if sys.version_info < (3, 11):
    import tomli as tomllib
    from exceptiongroup import BaseExceptionGroup
else:
    import tomllib

if TYPE_CHECKING:
    from typing_extensions import ParamSpec

    PS = ParamSpec("PS")

HOME: Final = trio.Path(getenv("HOME", path.expanduser("~")))
XDG_DATA_HOME: Final = trio.Path(
    getenv("XDG_DATA_HOME", HOME / ".local" / "share"),
)
XDG_CONFIG_HOME: Final = trio.Path(getenv("XDG_CONFIG_HOME", HOME / ".config"))

FILE_TITLE: Final = __title__.lower().replace(" ", "-").replace("-", "_")
CONFIG_PATH: Final = XDG_CONFIG_HOME / FILE_TITLE
DATA_PATH: Final = XDG_DATA_HOME / FILE_TITLE
MAIN_CONFIG: Final = CONFIG_PATH / "config.toml"

T = TypeVar("T")


def combine_end(data: Iterable[str], final: str = "and") -> str:
    """Return comma separated string of list of strings with last item phrased properly."""
    data = list(data)
    if len(data) >= 2:
        data[-1] = f"{final} {data[-1]}"
    if len(data) > 2:
        return ", ".join(data)
    return " ".join(data)


app: Final = QuartTrio(  # pylint: disable=invalid-name
    __name__,
    static_folder="static",
    template_folder="templates",
)


schema_v_2_04 = schema.Version_2_04(DATA_PATH)


@app.route("/MineOSAPI/<version>/<script>.php", methods=("POST", "GET"))
@pretty_exception
async def handle_script(
    version: str,
    script: str,
) -> AsyncIterator[str] | api.Response:
    """Handle script endpoint."""
    if version == "2.04":
        if script == "verify":
            verify_token = request.args.get("token")
            if verify_token is None:
                return await stream_template(
                    "verify.html.jinja",
                    page_title="Verification was unsuccessful",
                    message="Where is token...",
                )
            verified = await schema_v_2_04.verify(verify_token)
            if not verified:
                return await stream_template(
                    "verify.html.jinja",
                    page_title="Verification was unsuccessful",
                    message="User with specified token doesn't exist!",
                )
            return await stream_template(
                "verify.html.jinja",
                page_title="Verification was successful",
                message="User successfully verified!",
            )
        multi_dict = await request.form
        form = multi_dict.to_dict()
        data = dict(ChainMap(form, request.args))
        response = await schema_v_2_04.script(script, data)
        if isinstance(response, tuple):
            response = response[0]
        # print(f"{response = }")
        print(f"Response = {pretty_format(response)}")
        return response
    return api.failure("Invalid version")


@app.get("/")
@pretty_exception
async def handle_root() -> AsyncIterator[str]:
    """Send root file."""
    return await stream_template("root.html.jinja")


@app.get("/debug")
@pretty_exception
async def handle_debug_get() -> AsyncIterator[str]:
    """Send debug file."""
    return await stream_template("debug.html.jinja")


try:
    import market_api

    def pretty_format(text: str) -> str:
        """Pretty format text."""
        obj = cast(
            "dict[str, Any]",
            market_api.lua_parser.parse_lua_table(text),
        )
        value = market_api.pretty_format_response(obj)
        assert isinstance(value, str)
        return value

except ImportError:

    def pretty_format(text: str) -> str:
        """Pretty format text."""
        return text


@app.post("/debug")
@pretty_exception
async def handle_debug_post() -> (
    tuple[AsyncIterator[str], int] | AsyncIterator[str]
):
    """Send debug file."""
    multi_dict = await request.form
    form = multi_dict.to_dict()
    script = form.get("script")
    if not script:
        return (
            await stream_template(
                "error_page.html.jinja",
                page_title="No script given",
                error_body="No script name submitted.",
                return_link="/debug",
            ),
            400,
        )
    post_data = form.get("post_data")
    if post_data is None:
        return (
            await stream_template(
                "error_page.html.jinja",
                page_title="No post data given",
                error_body="No post data name submitted.",
                return_link="/debug",
            ),
            400,
        )
    lines = form.get("post_data", "").splitlines()
    arguments: dict[str, str] = {}
    for line in lines:
        data = tuple(map(str.strip, line.split("=", 1)))
        arguments[data[0]] = data[-1]

    raw_response = await schema_v_2_04.script(script, arguments)
    response_code = 200
    if isinstance(raw_response, tuple):
        response, response_code = raw_response
    else:
        response = raw_response

    post_autofill = "\n".join(f"{k}={v}" for k, v in arguments.items())

    response_lines = pretty_format(response).splitlines()

    response_html = htmlgen.wrap_tag(
        "textarea",
        "\n".join(line.replace(" ", "&nbsp;") for line in response_lines),
        readonly="",
        rows=len(response_lines),
        cols=90,
    )

    return await stream_template(
        "debug_post.html.jinja",
        response_code=response_code,
        response=response_html,
        script_autofill=script,
        post_autofill=post_autofill,
    )


@app.before_serving
async def startup() -> None:
    """Schedule backups."""
    app.add_background_task(backups.periodic_backups)


async def serve_async(app: QuartTrio, config_obj: Config) -> None:
    """Serve app within a nursery."""
    async with trio.open_nursery(strict_exception_groups=True) as nursery:
        await nursery.start(serve, app, config_obj)


def server_market(
    secure_bind_port: int | None = None,
    insecure_bind_port: int | None = None,
    ip_addr: str | None = None,
    hypercorn: dict[str, object] | None = None,
) -> None:
    """Asynchronous Entry Point."""
    if secure_bind_port is None and insecure_bind_port is None:
        raise ValueError(
            "Port must be specified with `port` and or `ssl_port`!",
        )

    if not ip_addr:
        ip_addr = find_ip()

    if not hypercorn:
        hypercorn = {}

    logs_path = DATA_PATH / "logs"
    if not path.exists(logs_path):
        makedirs(logs_path)

    print(f"Logs Path: {str(logs_path)!r}")
    print(f"Records Path: {str(DATA_PATH / 'records')!r}\n")

    try:
        # Hypercorn config setup
        config: dict[str, object] = {
            "accesslog": "-",
            "errorlog": logs_path / time.strftime("log_%Y_%m_%d.log"),
        }
        # Load things from user controlled toml file for hypercorn
        config.update(hypercorn)
        # Override a few particularly important details if set by user
        config.update(
            {
                "worker_class": "trio",
            },
        )
        # Make sure address is in bind

        if insecure_bind_port is not None:
            raw_bound = config.get("insecure_bind", [])
            if not isinstance(raw_bound, Iterable):
                raise ValueError(
                    "main.bind must be an iterable object (set in config file)!",
                )
            bound = set(raw_bound)
            bound |= {f"{ip_addr}:{insecure_bind_port}"}
            config["insecure_bind"] = bound

            # If no secure port, use bind instead
            if secure_bind_port is None:
                config["bind"] = config["insecure_bind"]
                config["insecure_bind"] = []

            insecure_locations = combine_end(
                f"http://{addr}" for addr in sorted(bound)
            )
            print(f"Serving on {insecure_locations} insecurely")

        if secure_bind_port is not None:
            raw_bound = config.get("bind", [])
            if not isinstance(raw_bound, Iterable):
                raise ValueError(
                    "main.bind must be an iterable object (set in config file)!",
                )
            bound = set(raw_bound)
            bound |= {f"{ip_addr}:{secure_bind_port}"}
            config["bind"] = bound

            secure_locations = combine_end(
                f"http://{addr}" for addr in sorted(bound)
            )
            print(f"Serving on {secure_locations} securely")

        app.config["EXPLAIN_TEMPLATE_LOADING"] = False

        # We want pretty html, no jank
        app.jinja_options = {
            "trim_blocks": True,
            "lstrip_blocks": True,
        }

        app.add_url_rule("/<path:filename>", "static", app.send_static_file)

        config_obj = Config.from_mapping(config)

        print("(CTRL + C to quit)")

        trio.run(serve_async, app, config_obj)
    except BaseExceptionGroup as exc:
        caught = False
        for ex in exc.exceptions:
            if isinstance(ex, KeyboardInterrupt):
                print("Shutting down from keyboard interrupt")
                caught = True
                break
        if not caught:
            raise


DEFAULT_CONFIG_TOML: Final = """[main]
# Port server should run on.
# You might want to consider changing this to 80
port = 3004

# Port for SSL secured server to run on
#ssl_port = 443

# Helpful stack exchange website question on how to allow non root processes
# to bind to lower numbered ports
# https://superuser.com/questions/710253/allow-non-root-process-to-bind-to-port-80-and-443
# Answer I used: https://superuser.com/a/1482188/1879931

[hypercorn]
# See https://hypercorn.readthedocs.io/en/latest/how_to_guides/configuring.html#configuration-options
use_reloader = false
# SSL configuration details
#certfile = "/home/<your_username>/letsencrypt/config/live/<your_domain_name>.duckdns.org/fullchain.pem"
#keyfile = "/home/<your_username>/letsencrypt/config/live/<your_domain_name>.duckdns.org/privkey.pem"
"""


def run() -> None:
    """Run scanner server."""
    parser = argparse.ArgumentParser(
        description="Python MineOS App Market Server Reimplementation.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__title__} v{__version__}",
        help="Show the program version and exit.",
    )
    parser.add_argument(
        "--create-default-config",
        action="store_true",
        help="Create or overwrite the default configuration file.",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Bind to localhost (127.0.0.1) instead of public ip address.",
    )

    args = parser.parse_args()

    if args.create_default_config:
        print(
            f"Creating/overwriting configuration file located at {str(MAIN_CONFIG)!r} with default...",
        )
        if not path.exists(CONFIG_PATH):
            makedirs(CONFIG_PATH)

        with open(MAIN_CONFIG, "w", encoding="utf-8") as fp:
            fp.write(DEFAULT_CONFIG_TOML)

        print("Action complete.")
        return

    if path.exists(MAIN_CONFIG):
        print(f"Reading configuration file {str(MAIN_CONFIG)!r}...\n")

        with open(MAIN_CONFIG, "rb") as fp:
            config = tomllib.load(fp)
    else:
        print(
            f"Configuration file {str(MAIN_CONFIG)!r} not found, loading default.",
        )
        config = tomllib.loads(DEFAULT_CONFIG_TOML)

    main_section = config.get("main", {})

    insecure_bind_port = main_section.get("port", None)
    secure_bind_port = main_section.get("ssl_port", None)

    hypercorn: dict[str, object] = config.get("hypercorn", {})

    ip_address: str | None = None
    if args.local:
        ip_address = "127.0.0.1"

    try:
        server_market(
            secure_bind_port=secure_bind_port,
            insecure_bind_port=insecure_bind_port,
            ip_addr=ip_address,
            hypercorn=hypercorn,
        )
    finally:
        database.unload_all()


if __name__ == "__main__":
    run()
