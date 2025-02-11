"""Generate pages for the web server."""

# Programmed by CoolCat467

from __future__ import annotations

# Generate pages for the web server
# Copyright (C) 2023-2024  CoolCat467
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

__title__ = "Generate Pages"
__author__ = "CoolCat467"


import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

from market_server import htmlgen, server

if TYPE_CHECKING:
    from collections.abc import Callable

MODULE: Final = Path(__file__).absolute().parent
SOURCE_ROOT: Final = MODULE.parent.parent

TEMPLATE_FOLDER: Final = MODULE / "templates"
TEMPLATE_FUNCTIONS: dict[Path, Callable[[], str]] = {}
STATIC_FOLDER: Final = MODULE / "static"
STATIC_FUNCTIONS: dict[Path, Callable[[], str]] = {}


def save_content(path: Path, content: str) -> None:
    """Save content to given path."""
    path.write_text(content + "\n", encoding="utf-8")
    print(f"Saved content to {path}")


def save_template_as(
    filename: str,
) -> Callable[[Callable[[], str]], Callable[[], str]]:
    """Save generated template as filename."""
    path = TEMPLATE_FOLDER / f"{filename}.html.jinja"

    def function_wrapper(function: Callable[[], str]) -> Callable[[], str]:
        if path in TEMPLATE_FUNCTIONS:
            raise NameError(
                f"{filename!r} already exists as template filename",
            )
        TEMPLATE_FUNCTIONS[path] = function
        return function

    return function_wrapper


def save_static_as(
    filename: str,
) -> Callable[[Callable[[], str]], Callable[[], str]]:
    """Save generated static file as filename."""
    path = STATIC_FOLDER / filename

    def function_wrapper(function: Callable[[], str]) -> Callable[[], str]:
        if path in STATIC_FUNCTIONS:
            raise NameError(f"{filename!r} already exists as static filename")
        STATIC_FUNCTIONS[path] = function
        return function

    return function_wrapper


@save_static_as("style.css")
def generate_style_css() -> str:
    """Generate style.css static file."""
    mono = "SFMono-Regular,SF Mono,Menlo,Consolas,Liberation Mono,monospace"
    return "\n".join(
        (
            htmlgen.css(
                ("*", "*::before", "*::after"),
                box_sizing="border-box",
                font_family="Lucida Console",
            ),
            htmlgen.css(("h1", "footer"), text_align="center"),
            htmlgen.css(("html", "body"), height="100%"),
            htmlgen.css(
                "body",
                line_height=1.5,
                _webkit_font_smoothing="antialiased",
                display="flex",
                flex_direction="column",
            ),
            htmlgen.css(".content", flex=(1, 0, "auto")),
            htmlgen.css(
                ".footer",
                flex_shrink=0,
            ),
            htmlgen.css(
                ("img", "picture", "video", "canvas", "svg"),
                display="block",
                max_width="100%",
            ),
            htmlgen.css(
                ("input", "button", "textarea", "select"),
                font="inherit",
            ),
            htmlgen.css(
                ("p", "h1", "h2", "h3", "h4", "h5", "h6"),
                overflow_wrap="break-word",
            ),
            htmlgen.css(
                ("#root", "#__next"),
                isolation="isolate",
            ),
            htmlgen.css(
                "code",
                padding=("0.2em", "0.4em"),
                background_color="rgba(158,167,179,0.4)",
                border_radius="6px",
                font_family=mono,
                line_height=1.5,
            ),
            htmlgen.css(
                "::placeholder",
                font_style="italic",
            ),
            htmlgen.css(
                ".box",
                background="ghostwhite",
                padding="0.5%",
                border_radius="4px",
                border=("2px", "solid", "black"),
                margin="0.5%",
                width="fit-content",
            ),
            htmlgen.css(
                "#noticeText",
                font_size="10px",
                display="inline-block",
                white_space="nowrap",
            ),
            htmlgen.css(
                'input[type="submit"]',
                border=("1.5px", "solid", "black"),
                border_radius="4px",
                padding="0.5rem",
                margin_left="0.5rem",
                margin_right="0.5rem",
                min_width="min-content",
            ),
        ),
    )


def template(
    title: str,
    body: str,
    *,
    head: str = "",
    body_tag: dict[str, htmlgen.TagArg] | None = None,
    lang: str = "en",
) -> str:
    """HTML Template for application."""
    head_data = "\n".join(
        (
            htmlgen.tag(
                "link",
                rel="apple-touch-icon",
                sizes="180x180",
                href="/apple-touch-icon.png",
            ),
            htmlgen.tag(
                "link",
                rel="icon",
                type_="image/png",
                sizes="32x32",
                href="/favicon-32x32.png",
            ),
            htmlgen.tag(
                "link",
                rel="icon",
                type_="image/png",
                sizes="16x16",
                href="/favicon-16x16.png",
            ),
            htmlgen.tag(
                "link",
                rel="manifest",
                href="/site.webmanifest",
            ),
            htmlgen.tag(
                "link",
                rel="mask-icon",
                href="/safari-pinned-tab.svg",
                color="#5bbad5",
            ),
            htmlgen.tag(
                "meta",
                name="msapplication-TileColor",
                content="#da532c",
            ),
            htmlgen.tag(
                "meta",
                name="theme-color",
                content="#ffffff",
            ),
            htmlgen.tag(
                "link",
                rel="stylesheet",
                type_="text/css",
                href="/style.css",
            ),
            head,
        ),
    )

    join_body = (
        htmlgen.wrap_tag("h1", title, False),
        body,
    )

    footer = f"{server.__title__} v{server.__version__} © {server.__author__}"

    body_data = "\n".join(
        (
            htmlgen.wrap_tag(
                "div",
                "\n".join(join_body),
                class_="content",
            ),
            htmlgen.wrap_tag(
                "footer",
                "\n".join(
                    (
                        htmlgen.wrap_tag(
                            "i",
                            "If you're reading this, the web server was installed correctly.™",
                            block=False,
                        ),
                        htmlgen.tag("hr"),
                        htmlgen.wrap_tag(
                            "p",
                            footer,
                            block=False,
                        ),
                    ),
                ),
            ),
        ),
    )

    return htmlgen.template(
        title,
        body_data,
        head=head_data,
        body_tag=body_tag,
        lang=lang,
    )


@save_template_as("error_page")
def generate_error_page() -> str:
    """Generate error response page."""
    error_text = htmlgen.wrap_tag("p", htmlgen.jinja_expression("error_body"))
    content = "\n".join(
        (
            error_text,
            htmlgen.tag("br"),
            htmlgen.jinja_if_block(
                {
                    "return_link": "\n".join(
                        (
                            htmlgen.create_link(
                                htmlgen.jinja_expression("return_link"),
                                "Return to previous page",
                            ),
                            htmlgen.tag("br"),
                        ),
                    ),
                },
            ),
            htmlgen.create_link("/", "Return to main page"),
        ),
    )
    body = htmlgen.contain_in_box(content)
    return template(
        htmlgen.jinja_expression("page_title"),
        body,
    )


@save_template_as("verify")
def generate_verify_page() -> str:
    """Generate verify page."""
    ##    return """<head>
    ##	<meta charset="utf-8">
    ##	<title>Verification was successful</title>
    ##	<style>
    ##		.body {
    ##			background-image: url(background.jpg);
    ##			background-size: cover;
    ##			border: 2px dashed #f69c55;
    ##		}
    ##		.centeredText {
    ##			font: normal small-caps 30px Arial;
    ##			color: #FFF;
    ##			text-shadow: 2px 2px 25px #000;
    ##
    ##			position: absolute;
    ##			top: 40%;
    ##			left: 50%;
    ##			transform: translate(-50%, -50%);
    ##		}
    ##	</style>
    ##</head>
    ##<body class = "body">
    ##	<p class = "centeredText">User with specified token doesn't exists!</p>
    ##</body>"""
    content = htmlgen.jinja_expression("message")
    body = htmlgen.contain_in_box(content)
    return template(
        htmlgen.jinja_expression("page_title"),
        body,
    )


@save_static_as("root.html")
def generate_root_page() -> str:
    """Generate root page."""
    content = htmlgen.bullet_list(
        (
            htmlgen.create_link(
                "/MineOSAPI/2.04/statistics.php",
                "View Statistics",
            ),
            htmlgen.create_link(
                "/debug",
                "Debug",
            ),
        ),
    )
    body = htmlgen.contain_in_box(content)
    return template(
        server.__title__,
        body,
    )


@save_static_as("debug.html")
def generate_debug_page() -> str:
    """Generate debug page."""
    form_contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "script",
                "Script",
                attrs={"required": ""},
            ),
            "\n".join(
                (
                    htmlgen.wrap_tag(
                        "label",
                        "Post Data",
                        block=False,
                        for_="post_area",
                    ),
                    htmlgen.wrap_tag(
                        "textarea",
                        "",
                        block=False,
                        name="post_data",
                        id_="post_area",
                        rows=5,
                        cols=80,
                    ),
                ),
            ),
        ),
    )
    form = htmlgen.form("debug_form", form_contents, "Post", "Debug Form")
    body = htmlgen.contain_in_box(form)
    return template(
        "Debug Form",
        body,
    )


@save_template_as("debug_post")
def generate_debug_post_page() -> str:
    """Generate debug page."""
    code = htmlgen.jinja_expression("response_code")
    response = htmlgen.contain_in_box(
        htmlgen.jinja_expression("response"),
        f"Response (code {code})",
    )
    form_contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "script",
                "Script",
                attrs={
                    "value": htmlgen.jinja_expression("script_autofill"),
                    "required": "",
                },
            ),
            "\n".join(
                (
                    htmlgen.wrap_tag(
                        "label",
                        "Post Data",
                        block=False,
                        for_="post_area",
                    ),
                    htmlgen.wrap_tag(
                        "textarea",
                        htmlgen.jinja_expression("post_autofill"),
                        block=False,
                        name="post_data",
                        id_="post_area",
                        rows=5,
                        cols=80,
                    ),
                ),
            ),
        ),
    )
    form = htmlgen.form("debug_form", form_contents, "Post", "Debug Form")
    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            response,
        ),
    )
    return template(
        "Debug Response",
        body,
    )


def matches_disk_files(new_files: dict[Path, str]) -> bool:
    """Return if all new file contents match old file contents.

    Copied from src/trio/_tools/gen_exports.py, dual licensed under
    MIT and APACHE2.
    """
    for path, new_source in new_files.items():
        if not path.exists():
            return False
        # Strip trailing newline `save_content` adds.
        old_source = path.read_text(encoding="utf-8")[:-1]
        if old_source != new_source:
            return False
    return True


def process(do_test: bool) -> int:
    """Generate all page templates and static files. Return exit code."""
    new_files: dict[Path, str] = {}
    for filename, function in TEMPLATE_FUNCTIONS.items():
        new_files[filename] = function()
    for filename, function in STATIC_FUNCTIONS.items():
        new_files[filename] = function()

    matches_disk = matches_disk_files(new_files)

    if do_test:
        if not matches_disk:
            print("Generated sources are outdated. Please regenerate.")
            return 1
    elif not matches_disk:
        for path, new_source in new_files.items():
            save_content(path, new_source)
        print("\nRegenerated sources successfully.")
        # With pre-commit integration, show that we edited files.
        return 1
    print("Generated sources are up to date.")
    return 0


def run() -> int:
    """Regenerate all generated files."""
    parser = argparse.ArgumentParser(
        description="Generate static and template files",
    )
    parser.add_argument(
        "--test",
        "-t",
        action="store_true",
        help="test if code is still up to date",
    )
    parsed_args = parser.parse_args()

    # Double-check we found the right directory
    assert (SOURCE_ROOT / "LICENSE").exists()

    return process(do_test=parsed_args.test)


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    sys.exit(run())
