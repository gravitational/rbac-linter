from role_analyzer import (
    requires_user_traits,
    parse_constraint,
    AnyValueConstraint,
    StringConstraint,
    RegexConstraint,
    UserTraitConstraint,
    InterpolationConstraint,
    EmailFunctionConstraint,
    RegexReplaceFunctionConstraint,
)


def parse_match_any_constraint():
    unparsed = "*"
    expected = AnyValueConstraint(unparsed)
    assert not requires_user_traits(unparsed), unparsed
    actual = parse_constraint(unparsed)
    assert expected == actual, unparsed


def test_parse_template_constraint():
    values = [
        ("internal", "key", None),
        ("external", "key", None),
        ("internal", "key", "inner"),
        ("external", "key", "inner"),
    ]

    for value in values:
        expected = UserTraitConstraint(*value)
        unparsed = (
            f"{{{{{expected.trait_type}.{expected.trait_key}}}}}"
            if None == expected.inner_trait_key
            else f'{{{{{expected.trait_type}.{expected.trait_key}["{expected.inner_trait_key}"]}}}}'
        )
        assert requires_user_traits(unparsed), unparsed
        actual = parse_constraint(unparsed)
        assert expected == actual, unparsed


def test_parse_interpolation_constraint():
    values = [
        ("prefix", "internal", "key", None, "suffix"),
        ("prefix", "external", "key", None, "suffix"),
        ("prefix", "internal", "key", "inner", "suffix"),
        ("prefix", "external", "key", "inner", "suffix"),
    ]

    for value in values:
        expected = InterpolationConstraint(*value)
        unparsed = (
            f"{expected.prefix}{{{{{expected.trait_type}.{expected.trait_key}}}}}{expected.suffix}"
            if None == expected.inner_trait_key
            else f'{expected.prefix}{{{{{expected.trait_type}.{expected.trait_key}["{expected.inner_trait_key}"]}}}}{expected.suffix}'
        )
        assert requires_user_traits(unparsed), unparsed
        actual = parse_constraint(unparsed)
        assert expected == actual, unparsed


def test_parse_email_function_constraint():
    values = [
        ("internal", "key", None),
        ("external", "key", None),
        ("internal", "key", "inner"),
        ("external", "key", "inner"),
    ]

    for value in values:
        expected = EmailFunctionConstraint(*value)
        unparsed = (
            f"{{{{email.local({expected.trait_type}.{expected.trait_key})}}}}"
            if None == expected.inner_trait_key
            else f'{{{{email.local({expected.trait_type}.{expected.trait_key}["{expected.inner_trait_key}"])}}}}'
        )
        assert requires_user_traits(unparsed), unparsed
        actual = parse_constraint(unparsed)
        assert expected == actual, unparsed


def test_parse_regexp_replace_function_constraint():
    values = [
        ("internal", "key", None, "pattern", "replacement"),
        ("external", "key", None, "pattern", "replacement"),
        ("internal", "key", "inner", "pattern", "replacement"),
        ("external", "key", "inner", "pattern", "replacement"),
    ]

    for value in values:
        expected = RegexReplaceFunctionConstraint(*value)
        unparsed = (
            f'{{{{regexp.replace({expected.trait_type}.{expected.trait_key}, "{expected.pattern}", "{expected.replace}")}}}}'
            if None == expected.inner_trait_key
            else f'{{{{regexp.replace({expected.trait_type}.{expected.trait_key}["{expected.inner_trait_key}"], "{expected.pattern}", "{expected.replace}")}}}}'
        )
        assert requires_user_traits(unparsed), unparsed
        actual = parse_constraint(unparsed)
        assert expected == actual, unparsed


def test_parse_regex_constraint():
    values = [
        r"a{3}",
        r"aa*",
        r"a*a",
        r"(ab)*a",
        r"a(ba)*",
        r"[\d]*",
        r"[0-9]*",
        r"[\D]*",
        r"[^\d]*",
        r"[\s]*",
        r"[ \t\n\r\f\v]*",
        r"[\S]+",
        r"[^ \t\n\r\f\v]+",
        r"[\w]?",
        r"[a-zA-Z0-9_]?",
        r"[\W]{3,5}",
        r"[^a-zA-Z0-9_]{3,5}",
        r".{0,2}",
        r".?.?",
        r"[abc]d",
        r"(ad|bd|cd)",
        r"[a-c]{10-11}",
        r"[abc]{10-11}",
    ]

    for value in values:
        unparsed = value
        assert not requires_user_traits(unparsed), unparsed
        actual = parse_constraint(unparsed)
        assert isinstance(actual, RegexConstraint), unparsed


def test_parse_string_constraint():
    values = ["foo", "bar", "baz", "foobar", "鑰匙", "∀∃"]

    for value in values:
        expected = StringConstraint(value)
        unparsed = value
        assert not requires_user_traits(unparsed), unparsed
        actual = parse_constraint(unparsed)
        assert expected == actual, unparsed
