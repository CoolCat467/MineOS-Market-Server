"""HTML Generation - Generate HTML & CSS programmatically.

Copyright (C) 2022-2024  CoolCat467

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

__title__ = "HTML Generation"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: nocover
    from collections.abc import Generator, Iterable, Mapping


def indent(level: int, text: str) -> str:
    """Indent text by level of spaces."""
    prefix = " " * level
    return "\n".join(prefix + line for line in text.splitlines())


def deindent(level: int, text: str) -> str:
    """Undo indent on text by level of characters."""
    prefix = " " * level
    return "\n".join(line.removeprefix(prefix) for line in text.splitlines())


TagArg = str | int | float | bool


def _quote_strings(values: Iterable[TagArg]) -> Generator[str, None, None]:
    """Wrap string arguments with spaces in quotes."""
    for value in values:
        if isinstance(value, str) and " " in value:
            yield f'"{value}"'
            continue
        yield f"{value}"


def _key_to_html_property(key: str) -> str:
    """Convert a key to an HTML property.

    This function takes a string `key` and returns a modified version
    of the string that can be used as an HTML property in an HTML tag.
    """
    return key.removesuffix("_").replace("_", "-")


def _generate_css_declarations(
    properties: dict[str, TagArg | list[TagArg] | tuple[TagArg, ...]],
) -> Generator[str, None, None]:
    """Yield declarations."""
    for key, values in properties.items():
        property_ = _key_to_html_property(key)
        wrap = values if isinstance(values, list | tuple) else (values,)
        value = " ".join(_quote_strings(wrap))
        yield f"{property_}: {value}"


def css_style(
    **kwargs: TagArg | list[TagArg] | tuple[TagArg, ...],
) -> list[str]:
    """Return CSS style data."""
    return [f"{prop};" for prop in _generate_css_declarations(kwargs)]


def css_block(
    selector: str | list[str] | tuple[str, ...],
    content: str,
) -> str:
    """Return CSS block."""
    if isinstance(selector, list | tuple):
        selector = ", ".join(selector)
    properties = indent(2, content)
    return f"{selector} {{\n{properties}\n}}"


def css(
    selector: str | list[str] | tuple[str, ...],
    /,
    **kwargs: TagArg | list[TagArg] | tuple[TagArg, ...],
) -> str:
    """Return CSS block."""
    properties = "\n".join(css_style(**kwargs))
    return css_block(selector, properties)


def _generate_html_attributes(
    args: dict[str, TagArg],
) -> Generator[str, None, None]:
    """Remove trailing underscores for arguments."""
    for name, value in args.items():
        key = _key_to_html_property(name)
        yield f'{key}="{value}"'


def tag(type_: str, /, **kwargs: TagArg) -> str:
    """Return HTML tag. Removes trailing underscore from argument names."""
    args = ""
    if kwargs:
        args = " " + " ".join(_generate_html_attributes(kwargs))
    return f"<{type_}{args}>"


def wrap_tag(
    type_: str,
    value: str,
    /,
    block: bool = True,
    **kwargs: TagArg,
) -> str:
    """Wrap value in HTML tag.

    If block, indent value
    """
    if block and value:
        value = f"\n{indent(2, value)}\n"
    start_tag = tag(type_, **kwargs)
    return f"{start_tag}{value}</{type_}>"


def wrap_comment(text: str, /, inline: bool = False) -> str:
    """Wrap text in comment block.

    If inline, comment does not have linebreaks before and after text
    """
    if not inline and text:
        text = f"\n{text}\n"
    if "-->" in text:
        raise ValueError("Attempted comment escape")
    escaped_text = text.replace("-->", "")
    return f"<!--{escaped_text}-->"


def template(
    title: str,
    body: str,
    *,
    head: str = "",
    body_tag: dict[str, TagArg] | None = None,
    lang: str = "en",
) -> str:
    """Get template for page."""
    body_tag_dict = {} if body_tag is None else body_tag
    head_content = "\n".join(
        (
            tag("meta", charset="utf-8"),
            tag(
                "meta",
                name="viewport",
                content="width=device-width, initial-scale=1",
            ),
            wrap_tag("title", title, False),
            head,
        ),
    )

    html_content = "\n".join(
        (
            wrap_tag("head", head_content),
            wrap_tag("body", body, block=True, **body_tag_dict),
        ),
    )

    return "\n".join(
        (
            tag("!DOCTYPE HTML"),
            wrap_tag(
                "html",
                html_content,
                lang=lang,
            ),
        ),
    )


def contain_in_box(inside: str, name: str | None = None) -> str:
    """Contain HTML in a box."""
    if name is not None:
        inside = "\n".join(
            (
                wrap_tag("span", name, block=False),
                tag("br"),
                inside,
            ),
        )
    return wrap_tag(
        "div",
        inside,
        class_="box",
    )


def input_field(
    field_id: str,
    field_title: str | None,
    *,
    field_name: str | None = None,
    field_type: str = "text",
    attrs: Mapping[str, TagArg] | None = None,
) -> str:
    """Generate HTML input field.

    If `field_name` is left as `None`, it will default to `field_id`.

    If any attribute from attrs conflicts with an attribute defined from
    other parameters, a ValueError is raised
    """
    if field_name is None:
        field_name = field_id
    lines = []
    args: dict[str, TagArg] = {
        "type": field_type,
        "id": field_id,
        "name": field_name,
    }
    if args["type"] == "text":
        # Browser defaults to text
        del args["type"]
    if attrs is not None:
        for key, value in attrs.items():
            property_ = _key_to_html_property(key)
            if property_ not in args:
                args[property_] = value
            else:
                raise ValueError(
                    f"Attribute {key!r} conflicts with an internal attribute",
                )
    lines.append(tag("input", **args))
    if field_title is not None:
        lines.append(wrap_tag("label", field_title, False, for_=field_id))
    # If label should be before, reverse.
    if field_type in {"number", "text"}:
        return "\n".join(reversed(lines))
    return "\n".join(lines)


def select_dict(
    submit_name: str,
    options: Mapping[str, str | Mapping[str, TagArg]],
    default: str | None = None,
) -> str:
    """Create radio select from dictionary.

    Options is a mapping of display text to submit as
    field values and or field types.
    """
    lines = []
    for count, (display, value_data) in enumerate(options.items()):
        if isinstance(value_data, str):
            # If just field value, default to radio
            field_type = "radio"
            attributes = {
                "value": value_data,
            }
        else:
            # Otherwise user can define field type.
            attributes = dict(value_data)  # type: ignore[arg-type]
            field_type = attributes.pop("type", "radio")
        if (
            field_type == "radio"
            and "value" in attributes
            and attributes["value"] == default
        ):
            attributes["checked"] = "checked"
        lines.append(
            input_field(
                field_id=f"{submit_name}_{count}",
                field_title=display,
                field_name=submit_name,
                field_type=field_type,
                attrs=attributes,
            ),
        )
        lines.append("<br>")
    return "\n".join(lines)


def select_box(
    submit_name: str,
    options: Mapping[str, str | Mapping[str, TagArg]],
    default: str | None = None,
    box_title: str | None = None,
) -> str:
    """Create radio select value box from dictionary and optional names.

    See `select_dict` for more information on arguments
    """
    radios = select_dict(submit_name, options, default)
    return contain_in_box("<br>\n" + radios, box_title)


def bullet_list(values: Iterable[str], **kwargs: TagArg) -> str:
    """Return HTML bulleted list from values."""
    display = "\n".join(wrap_tag("li", v, block=False) for v in values)
    return wrap_tag("ul", display, block=True, **kwargs)


def create_link(reference: str, display: str) -> str:
    """Create link to reference."""
    return wrap_tag("a", display, False, href=reference)


def link_list(links: dict[str, str], **kwargs: TagArg) -> str:
    """Return HTML bulleted list of links.

    Keys are the reference, values are displayed text
    """
    values = [create_link(ref, disp) for ref, disp in links.items()]
    return bullet_list(values, **kwargs)


def form(
    form_id: str,
    contents: str,
    submit_display: str,
    form_title: str | None = None,
) -> str:
    """Return an HTML form.

    This function generates an HTML form with the specified `form_id` and
    `contents`, along with a submit button with the text `submit_display`.
    If `form_title` is provided, the function generates a bolded title
    for the form.

    Args:
    ----
        form_id: ID of the form.
        contents: Contents of the form, including input fields, text, and or other HTML elements.
        submit_display: Text to display on the submit button for the form.
        form_title: Optional title of the form.

    Returns:
    -------
        A string containing the HTML for the generated form.

    Raises:
    ------
        TypeError: If `form_id`, `contents`, or `submit_display` are not
            strings.

    """
    submit = input_field(
        f"{form_id}_submit_button",
        None,
        field_type="submit",
        attrs={
            "value": submit_display,
        },
    )
    html = f"""{contents}
<br>
{submit}"""
    title = ""
    if form_title is not None:
        title = wrap_tag("b", form_title, block=False) + "\n"
    return title + wrap_tag("form", html, True, name=form_id, method="post")


def jinja_statement(value: str) -> str:
    """Wrap value in jinja statement block."""
    return f"{{% {value} %}}"


def jinja_expression(value: str) -> str:
    """Wrap value in jinja expression block."""
    return f"{{{{ {value} }}}}"


def jinja_comment(value: str) -> str:
    """Wrap value in jinja comment block."""
    return f"{{# {value} #}}"


def jinja_if_block(conditions: dict[str, str], block: bool = True) -> str:
    """Generate jinja if / if else block from dictionary.

    Keys are conditions to check, values are content if true.
    "" key means else block.
    """
    contents = []
    has_else = False
    for count, (condition, content) in enumerate(conditions.items()):
        statement = "if" if count == 0 else "elif"
        cond = ""
        if condition:
            if has_else:
                raise ValueError("Found condition after else block defined")
            cond = f" {condition}"
        else:
            if not count:
                raise ValueError(
                    "There must be at least one condition for there to be an else block",
                )
            has_else = True
            # because of how dictionaries work it should not be possible
            # for there to be more than one key matching ""
            statement = "else"
        contents.append(jinja_statement(f"{statement}{cond}"))
        contents.append(content)
    contents.append(jinja_statement("endif"))
    join = "\n" if block else ""
    return join.join(contents)


def jinja_for_loop(
    results: Iterable[str],
    iterate: str,
    content: str,
    filter_: str | None = None,
    else_content: str | None = None,
) -> str:
    """Generate jinja for loop block.

    Ends up being something like:
    for {results} in {iterate} [if {filter_}]:
        {content}
    else: # If no results that matched filter
        {else_content}
    """
    result_items = ", ".join(results)
    filter_items = ""
    if filter_:
        filter_items = f" if {filter_}"
    for_tag = jinja_statement(f"for {result_items} in {iterate}{filter_items}")
    # content = indent(2, content)
    end = jinja_statement("endfor")
    if else_content:
        else_block = jinja_statement("else")
        # else_content = indent(2, else_content)
        end = f"{else_block}\n{else_content}\n{end}"
    return f"{for_tag}\n{content}\n{end}"


def jinja_arg_tag(
    type_: str,
    jinja_properties: Iterable[str],
    /,
    **kwargs: TagArg,
) -> str:
    """Return HTML tag. Removes trailing underscore from argument names."""
    args = " ".join(jinja_properties)
    if args:
        args = f" {args}"
    if kwargs:
        args = f"{args} " + " ".join(_generate_html_attributes(kwargs))
    return f"<{type_}{args}>"


def jinja_radio_select(
    submit_name: str,
    options_dict_name: str,
    default: str | None = None,
    else_content: str | None = None,
) -> str:
    """Create radio select from dictionary."""
    count = jinja_expression("loop.index0")
    cid = f"{submit_name}_{count}"
    args = {
        "type": "radio",
        "id": cid,
        "name": submit_name,
        "value": jinja_expression("value"),
    }
    jinja_properties: tuple[str, ...] = ()
    if default is not None:
        default_tag = " ".join(
            _generate_html_attributes({"checked": "checked"}),
        )
        jinja_properties = (
            jinja_if_block(
                {f"value == {default}": default_tag},
                block=False,
            ),
        )
    return jinja_for_loop(
        ("display", "value"),
        f"{options_dict_name}.items()",
        "\n".join(
            (
                jinja_arg_tag("input", jinja_properties, **args),
                wrap_tag(
                    "label",
                    jinja_expression("display"),
                    False,
                    **{"for": cid},
                ),
                tag("br"),
            ),
        ),
        else_content=else_content,
    )


def jinja_bullet_list(
    results: Iterable[str],
    iterate: str,
    content: str,
    filter_: str | None = None,
    else_content: str | None = None,
) -> str:
    """Return HTML bulleted list from values."""
    return wrap_tag(
        "ul",
        jinja_for_loop(
            results,
            iterate,
            wrap_tag("li", content, block=False),
            filter_=filter_,
            else_content=else_content,
        ),
    )


def jinja_block(
    title: str,
    content: str,
    scoped: bool = False,
    required: bool = False,
    block: bool = True,
) -> str:
    """Wrap content in jinja block named {title}.

    If block is True, put start block and end block
    expressions on lines of their own, otherwise leave
    everything on the same line.
    """
    if " " in title or not title:
        raise ValueError("Title must not contain spaces and must not be blank")

    join = "\n" if block else ""
    extra_tags = []
    if scoped:
        extra_tags.append("scoped")
    if required:
        extra_tags.append("required")
    tag_data = " " + " ".join(extra_tags) if extra_tags else ""
    # Title not required for endblock statement but nice for readability
    return join.join(
        (
            jinja_statement(f"block {title}{tag_data}"),
            content,
            jinja_statement(f"endblock {title}"),
        ),
    )


def jinja_extends(template_filename: str | Iterable[str]) -> str:
    """Return jinja extends statement from given template filename."""
    # Using if else instead of ternary because it makes it confusing from
    # a types perspective and less readable
    if isinstance(
        template_filename,
        str,
    ):  # ternary operator instead of if else
        filename = template_filename
    else:
        filename = "/".join(template_filename)
    return jinja_statement(f'extends "{filename}"')


def jinja_super_block() -> str:
    """Return jinja super() expression."""
    return jinja_expression("super()")


def jinja_number_plural(
    numeric_value: int | str,
    word: str,
) -> str:
    """Return word pluralized given numeric variable.

    If value of numeric value is not > 1, return `{word}`
    If value is > 1, return `{word}s`
    """
    return word + jinja_if_block(
        {
            f"{numeric_value} > 1": "s",
            f"{numeric_value} == 0": "s",
        },
        block=False,
    )
