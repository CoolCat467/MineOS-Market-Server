"""Test html generation."""

from __future__ import annotations

import pytest
from market_server import htmlgen


def test_indent_single() -> None:
    assert htmlgen.indent(4, "cat") == "    cat"


def test_indent_lines() -> None:
    assert htmlgen.indent(4, "cat\npotato") == "    cat\n    potato"


def test_indent_lines_indent_two() -> None:
    assert htmlgen.indent(2, "cat\npotato") == "  cat\n  potato"


def test_deindent_single() -> None:
    assert htmlgen.deindent(4, "    cat") == "cat"


def test_deindent_single_only_four() -> None:
    assert htmlgen.deindent(4, "     cat") == " cat"


def test_deindent_lines() -> None:
    assert htmlgen.deindent(4, "    cat\n    potato") == "cat\npotato"


def test_deindent_lines_level_seven() -> None:
    assert htmlgen.deindent(7, "       cat\n       potato") == "cat\npotato"


def test_css_style() -> None:
    assert htmlgen.css_style(
        value_="seven",
        property_with_should_be_dash="space value",
    ) == ["value: seven;", 'property-with-should-be-dash: "space value";']


def test_css_block() -> None:
    assert htmlgen.css_block("*", "content") == "* {\n  content\n}"


def test_css_multi_select() -> None:
    assert htmlgen.css_block(("*", "*::"), "content") == "*, *:: {\n  content\n}"


def test_css() -> None:
    assert htmlgen.css(("h1", "footer"), text_align="center") == "h1, footer {\n  text-align: center;\n}"


def test_css_multi() -> None:
    assert htmlgen.css(("h1", "footer"), text_align=("center", "left")) == "h1, footer {\n  text-align: center left;\n}"


@pytest.mark.parametrize(
    ("type_", "args", "expect"),
    [
        ("p", {}, "<p>"),
        ("p", {"fish": "false"}, '<p fish="false">'),
        ("i", {}, "<i>"),
        (
            "input",
            {"type": "radio", "id": "0", "name": "test", "value_": "Example"},
            '<input type="radio" id="0" name="test" value="Example">',
        ),
    ],
)
def test_tag(type_: str, args: dict[str, str], expect: str) -> None:
    assert htmlgen.tag(type_, **args) == expect


@pytest.mark.parametrize(
    ("type_", "value", "block", "args", "expect"),
    [
        ("p", "value", False, {}, "<p>value</p>"),
        ("p", "fish", False, {"fish": "false"}, '<p fish="false">fish</p>'),
        ("i", "italic", False, {}, "<i>italic</i>"),
        (
            "input",
            "seven",
            False,
            {"type": "radio", "id": "0", "name": "test", "value_": "Example"},
            '<input type="radio" id="0" name="test" value="Example">seven</input>',
        ),
    ],
)
def test_wrap_tag(
    type_: str,
    value: str,
    block: bool,
    args: dict[str, str],
    expect: str,
) -> None:
    assert htmlgen.wrap_tag(type_, value, block, **args) == expect


def test_wrap_comment() -> None:
    assert (
        htmlgen.wrap_comment("this is comment")
        == """<!--
this is comment
-->"""
    )


def test_wrap_comment_inline() -> None:
    assert htmlgen.wrap_comment("smol comment", inline=True) == "<!--smol comment-->"


def test_wrap_comment_avoid_hacks() -> None:
    with pytest.raises(ValueError, match="Attempted comment escape"):
        htmlgen.wrap_comment("-->haha now javascript hacks you", inline=True)


def test_template() -> None:
    assert (
        htmlgen.template(
            "Cat Page",
            "Cat Body",
            head="Cat Head",
            body_tag={"cat_name": "bob"},
            lang="lolcat",
        )
        == """<!DOCTYPE HTML>
<html lang="lolcat">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cat Page</title>
    Cat Head
  </head>
  <body cat-name="bob">
    Cat Body
  </body>
</html>"""
    )


def test_template_no_tag() -> None:
    assert (
        htmlgen.template(
            "Cat Page",
            "Cat Body",
            head="Cat Head",
        )
        == """<!DOCTYPE HTML>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cat Page</title>
    Cat Head
  </head>
  <body>
    Cat Body
  </body>
</html>"""
    )


def test_contain_in_box_none() -> None:
    assert (
        htmlgen.contain_in_box("inside woo")
        == """<div class="box">
  inside woo
</div>"""
    )


def test_contain_in_box_named() -> None:
    assert (
        htmlgen.contain_in_box("inside different", "Names here")
        == """<div class="box">
  <span>
    Names here
  </span>
  <br>
  inside different
</div>"""
    )


def test_select_dict() -> None:
    assert (
        htmlgen.select_dict("name_here", {"cat": "seven"})
        == """<input type="radio" id="name_here_0" name="name_here" value="seven">
<label for="name_here_0">cat</label>
<br>"""
    )


def test_select_dict_lots_default() -> None:
    assert (
        htmlgen.select_dict(
            "name_here",
            {"cat": "0", "fish": "1", "four": "3"},
            default="0",
        )
        == """<input type="radio" id="name_here_0" name="name_here" value="0" checked="checked">
<label for="name_here_0">cat</label>
<br>
<input type="radio" id="name_here_1" name="name_here" value="1">
<label for="name_here_1">fish</label>
<br>
<input type="radio" id="name_here_2" name="name_here" value="3">
<label for="name_here_2">four</label>
<br>"""
    )


def test_select_dict_checkbox() -> None:
    assert (
        htmlgen.select_dict(
            "breakfast_options",
            {
                "Syrup?": {"value": "yes_syrup", "type": "checkbox"},
                "Eggs?": {"value": "yes_eggs", "type": "checkbox"},
                "Bacon?": {"value": "yes_bacon", "type": "checkbox"},
            },
        )
        == """<input type="checkbox" id="breakfast_options_0" name="breakfast_options" value="yes_syrup">
<label for="breakfast_options_0">Syrup?</label>
<br>
<input type="checkbox" id="breakfast_options_1" name="breakfast_options" value="yes_eggs">
<label for="breakfast_options_1">Eggs?</label>
<br>
<input type="checkbox" id="breakfast_options_2" name="breakfast_options" value="yes_bacon">
<label for="breakfast_options_2">Bacon?</label>
<br>"""
    )


def test_select_box() -> None:
    assert (
        htmlgen.select_box(
            "name_here",
            {"cat": "seven"},
            box_title="click to add title",
        )
        == """<div class="box">
  <span>
    click to add title
  </span>
  <br>
  <br>
  <input type="radio" id="name_here_0" name="name_here" value="seven">
  <label for="name_here_0">cat</label>
  <br>
</div>"""
    )


def test_input_field_no_kwarg() -> None:
    assert (
        htmlgen.input_field("<id>", "woot")
        == """<input id="<id>" name="<id>">
<label for="<id>">woot</label>"""
    )


def test_input_field_with_type() -> None:
    assert (
        htmlgen.input_field("<id>", "woot", field_type="types woo")
        == """<input type="types woo" id="<id>" name="<id>">
<label for="<id>">woot</label>"""
    )


def test_input_field_attrs() -> None:
    assert (
        htmlgen.input_field(
            "<id>",
            "woot",
            field_type="types woo",
            attrs={"autoselect": ""},
        )
        == """<input type="types woo" id="<id>" name="<id>" autoselect="">
<label for="<id>">woot</label>"""
    )


def test_input_field_exception() -> None:
    with pytest.raises(
        ValueError,
        match="Attribute 'id' conflicts with an internal attribute",
    ):
        htmlgen.input_field(
            "field_id",
            "title",
            attrs={
                "id": "attempt_to_override_id",
            },
        )


def test_bullet_list() -> None:
    assert (
        htmlgen.bullet_list(["one", "two"], flag="bean")
        == """<ul flag="bean">
  <li>one</li>
  <li>two</li>
</ul>"""
    )


def test_create_link() -> None:
    assert htmlgen.create_link("/ref", "title of lonk") == '<a href="/ref">title of lonk</a>'


def test_link_list() -> None:
    assert (
        htmlgen.link_list({"/cat-page": "Cat memes", "/home": "Home page"})
        == """<ul>
  <li><a href="/cat-page">Cat memes</a></li>
  <li><a href="/home">Home page</a></li>
</ul>"""
    )


def test_form() -> None:
    assert (
        htmlgen.form(
            "form_id",
            "dis content woo",
            "hihi",
            "click to add title",
        )
        == """<b>click to add title</b>
<form name="form_id" method="post">
  dis content woo
  <br>
  <input type="submit" id="form_id_submit_button" name="form_id_submit_button" value="hihi">
</form>"""
    )


def test_form_no_title() -> None:
    assert (
        htmlgen.form("form_id", "dis content woo", "hihi")
        == """<form name="form_id" method="post">
  dis content woo
  <br>
  <input type="submit" id="form_id_submit_button" name="form_id_submit_button" value="hihi">
</form>"""
    )


def test_jinja_statement() -> None:
    assert htmlgen.jinja_statement("jinja exp") == "{% jinja exp %}"


def test_jinja_expression() -> None:
    assert htmlgen.jinja_expression("username") == "{{ username }}"


def test_jinja_comment() -> None:
    assert htmlgen.jinja_comment("comment") == "{# comment #}"


def test_jinja_if_block() -> None:
    assert (
        htmlgen.jinja_if_block(
            {
                'name == "cat"': "Hallos cat",
                'name == "fish"': "hallos fish",
                "name in users": "hallos user",
                "": "yay newfrien",
            },
        )
        == """{% if name == "cat" %}
Hallos cat
{% elif name == "fish" %}
hallos fish
{% elif name in users %}
hallos user
{% else %}
yay newfrien
{% endif %}"""
    )


def test_jinja_if_block_after_else_exception() -> None:
    with pytest.raises(
        ValueError,
        match="Found condition after else block defined",
    ):
        htmlgen.jinja_if_block(
            {
                'name == "cat"': "Hallos cat",
                "": "yay newfrien",
                'name == "fish"': "hallos fish",
            },
        )


def test_jinja_if_block_no_if_for_else_exception() -> None:
    with pytest.raises(
        ValueError,
        match="There must be at least one condition for there to be an else block",
    ):
        htmlgen.jinja_if_block(
            {
                "": "yay newfrien",
            },
        )


def test_jinja_for_loop() -> None:
    assert (
        htmlgen.jinja_for_loop(
            ("element",),
            "elements",
            "{{ loop.index }} - {{ element }}",
        )
        == """{% for element in elements %}
{{ loop.index }} - {{ element }}
{% endfor %}"""
    )


def test_jinja_for_loop_filter() -> None:
    assert (
        htmlgen.jinja_for_loop(
            ("element",),
            "elements",
            "{{ loop.index }} - {{ element }}",
            "element.startswith('cat')",
        )
        == """{% for element in elements if element.startswith('cat') %}
{{ loop.index }} - {{ element }}
{% endfor %}"""
    )


def test_jinja_for_loop_else_content() -> None:
    assert (
        htmlgen.jinja_for_loop(
            ("element",),
            "elements",
            "{{ loop.index }} - {{ element }}",
            "element.startswith('cat')",
            "There are no cat elements",
        )
        == """{% for element in elements if element.startswith('cat') %}
{{ loop.index }} - {{ element }}
{% else %}
There are no cat elements
{% endfor %}"""
    )


@pytest.mark.parametrize(
    ("type_", "props", "args", "expect"),
    [
        ("p", ("jinja",), {}, "<p jinja>"),
        ("p", (), {"fish": "false"}, '<p fish="false">'),
        ("p", ("jinja",), {"fish": "false"}, '<p jinja fish="false">'),
        ("i", (), {}, "<i>"),
        (
            "input",
            (),
            {"type": "radio", "id": "0", "name": "test", "value_": "Example"},
            '<input type="radio" id="0" name="test" value="Example">',
        ),
        (
            "input",
            ("jinja",),
            {"type": "radio", "id": "0", "name": "test", "value_": "Example"},
            '<input jinja type="radio" id="0" name="test" value="Example">',
        ),
    ],
)
def test_jinja_arg_tag(
    type_: str,
    props: tuple[str, ...],
    args: dict[str, str],
    expect: str,
) -> None:
    assert htmlgen.jinja_arg_tag(type_, props, **args) == expect


def test_jinja_radio_select() -> None:
    assert (
        htmlgen.jinja_radio_select("submits", "option_data")
        == """{% for display, value in option_data.items() %}
<input type="radio" id="submits_{{ loop.index0 }}" name="submits" value="{{ value }}">
<label for="submits_{{ loop.index0 }}">{{ display }}</label>
<br>
{% endfor %}"""
    )


def test_jinja_radio_select_default() -> None:
    assert (
        htmlgen.jinja_radio_select("submits", "option_data", "default text")
        == """{% for display, value in option_data.items() %}
<input {% if value == default text %}checked="checked"{% endif %} type="radio" id="submits_{{ loop.index0 }}" name="submits" value="{{ value }}">
<label for="submits_{{ loop.index0 }}">{{ display }}</label>
<br>
{% endfor %}"""
    )


def test_jinja_radio_select_else_content() -> None:
    assert (
        htmlgen.jinja_radio_select(
            "submits",
            "option_data",
            else_content="default text",
        )
        == """{% for display, value in option_data.items() %}
<input type="radio" id="submits_{{ loop.index0 }}" name="submits" value="{{ value }}">
<label for="submits_{{ loop.index0 }}">{{ display }}</label>
<br>
{% else %}
default text
{% endfor %}"""
    )


def test_jinja_bullet_list() -> None:
    assert (
        htmlgen.jinja_bullet_list(
            ("element",),
            "elements",
            "{{ element }}",
        )
        == """<ul>
  {% for element in elements %}
  <li>{{ element }}</li>
  {% endfor %}
</ul>"""
    )


def test_jinja_block() -> None:
    assert (
        htmlgen.jinja_block(
            "title_here",
            "hallos content",
        )
        == """{% block title_here %}
hallos content
{% endblock title_here %}"""
    )


def test_jinja_block_invalid_title() -> None:
    with pytest.raises(
        ValueError,
        match="Title must not contain spaces and must not be blank",
    ):
        htmlgen.jinja_block("name with spaces", "content")


def test_jinja_block_invalid_blank_title() -> None:
    with pytest.raises(
        ValueError,
        match="Title must not contain spaces and must not be blank",
    ):
        htmlgen.jinja_block("", "content")


def test_jinja_block_scoped() -> None:
    assert (
        htmlgen.jinja_block(
            "title_here",
            "hallos content",
            scoped=True,
        )
        == """{% block title_here scoped %}
hallos content
{% endblock title_here %}"""
    )


def test_jinja_block_required() -> None:
    assert (
        htmlgen.jinja_block(
            "title_here",
            "hallos content",
            required=True,
        )
        == """{% block title_here required %}
hallos content
{% endblock title_here %}"""
    )


def test_jinja_block_required_scoped() -> None:
    assert (
        htmlgen.jinja_block(
            "title_here",
            "hallos content",
            required=True,
            scoped=True,
        )
        == """{% block title_here scoped required %}
hallos content
{% endblock title_here %}"""
    )


def test_jinja_block_inline() -> None:
    assert (
        htmlgen.jinja_block(
            "title_here",
            "hallos content",
            block=False,
        )
        == """{% block title_here %}hallos content{% endblock title_here %}"""
    )


def test_jinja_extends() -> None:
    assert (
        htmlgen.jinja_extends(
            "template_filename",
        )
        == '{% extends "template_filename" %}'
    )


def test_jinja_extends_path() -> None:
    assert (
        htmlgen.jinja_extends(
            ("templates", "settings", "change_username.html.jinja"),
        )
        == '{% extends "templates/settings/change_username.html.jinja" %}'
    )


def test_jinja_super_block() -> None:
    assert htmlgen.jinja_super_block() == "{{ super() }}"


def test_jinja_number_plural() -> None:
    assert htmlgen.jinja_number_plural(3, "second") == "second{% if 3 > 1 %}s{% elif 3 == 0 %}s{% endif %}"
