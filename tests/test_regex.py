import sre_parse
from z3 import Distinct, Solver, sat, unsat  # type: ignore
from role_analyzer import regex_to_z3_expr


def test_regex_equality():
    regexes = [
        (r"aaa", r"a{3}"),
        (r"aa*", r"a*a"),
        (r"(ab)*a", r"a(ba)*"),
        (r"[\d]*", r"[0-9]*"),
        (r"[\D]*", r"[^\d]*"),
        (r"[\s]*", r"[ \t\n\r\f\v]*"),
        (r"[\S]+", r"[^ \t\n\r\f\v]+"),
        (r"[\w]?", r"[a-zA-Z0-9_]?"),
        (r"[\W]{3,5}", r"[^a-zA-Z0-9_]{3,5}"),
        (r".{0,2}", r".?.?"),
        (r"[abc]d", r"(ad|bd|cd)"),
        (r"[a-c]{10-11}", r"[abc]{10-11}"),
        (r".", r".{1}"),
    ]

    s = Solver()

    # Check for equivalence of each regex in the test set
    for regex in regexes:
        first, second = regex
        first_parsed = sre_parse.parse(first)
        second_parsed = sre_parse.parse(second)
        # Ensure we're testing the Z3 regex engine, not just the regex parser
        assert list(first_parsed) != list(second_parsed), regex

        s.push()
        first_expr = regex_to_z3_expr(first_parsed)
        second_expr = regex_to_z3_expr(second_parsed)
        s.add(Distinct(first_expr, second_expr))
        result = s.check()
        model = s.model() if sat == result else "NO_MODEL"
        assert unsat == result, f"{regex} : {model}"
        s.pop()

    # Triple each side of the regex and check for equivalence again
    # Temporarily removing this due to https://github.com/Z3Prover/z3/issues/5693
    # for regex in regexes:
    #  first, second = regex
    #  first = first + first + first
    #  second = second + second + second
    #  first_parsed = sre_parse.parse(first)
    #  second_parsed = sre_parse.parse(second)
    #  # Ensure we're testing the Z3 regex engine, not just the regex parser
    #  self.assertNotEqual(list(first_parsed), list(second_parsed), regex)
    #  s.push()
    #  first_expr = regex_to_z3_expr(first_parsed)
    #  second_expr = regex_to_z3_expr(second_parsed)
    #  s.add(Distinct(first_expr, second_expr))
    #  result = s.check()
    #  model = s.model() if sat == result else 'NO_MODEL'
    #  self.assertEqual(unsat, result, f'{(first, second)} : {model}')
    #  s.pop()
