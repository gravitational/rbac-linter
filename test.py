import sre_parse
import unittest
from z3 import *
from role_analyzer import regex_to_z3_expr

class TestRegexSolver(unittest.TestCase):

  def test_regex_equality(self):
    regexes = [
      ('aaa', 'a{3}'),
      ('aa*', 'a*a'),
      ('(ab)*a', 'a(ba)*'),
      ('[\d]*', '[0-9]*'),
      ('[\D]*', '[^\d]*'),
      ('[\s]*', '[ \t\n\r\f\v]*'),
      ('[\S]+', '[^ \t\n\r\f\v]+'),
      ('[\w]?', '[a-zA-Z0-9_]?'),
      ('[\W]{3,5}', '[^a-zA-Z0-9_]{3,5}'),
      ('.{0,2}', '.?.?'),
      ('[abc]d', '(ad|bd|cd)'),
      ('[a-c]{10-11}', '[abc]{10-11}')
    ]
    
    s = Solver()
    
    # Check for equivalence of each regex in the test set
    for regex in regexes:
      first, second = regex
      first_parsed = sre_parse.parse(first)
      second_parsed = sre_parse.parse(second)
      # Ensure we're testing the Z3 regex engine, not just the regex parser
      self.assertNotEqual(list(first_parsed), list(second_parsed), regex)

      s.push()
      first_expr = regex_to_z3_expr(first_parsed)
      second_expr = regex_to_z3_expr(second_parsed)
      s.add(Distinct(first_expr, second_expr))
      result = s.check()
      model = s.model() if sat == result else 'NO_MODEL'
      self.assertEqual(unsat, result, f'{regex} : {model}')
      s.pop()
    
    # Triple each side of the regex and check for equivalence again
    # Temporarily removing this due to https://github.com/Z3Prover/z3/issues/5693
    #for regex in regexes:
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
      
unittest.main()
