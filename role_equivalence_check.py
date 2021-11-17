import argparse
import logging
from role_analyzer import allows
import yaml
from z3 import *

def test_equivalence(r1, r2):
  r1 = allows(r1)
  r2 = allows(r2)
  s = Solver()
  s.add(Distinct(r1, r2))
  result = s.check()
  if unsat == result:
    print('Roles are equivalent.')
  elif sat == result:
    print('Roles are not equivalent; counterexample:')
    print(s.model())
  else:
    print(result)

parser = argparse.ArgumentParser(description='Check two roles for equivalence.')
parser.add_argument('first', metavar='FIRST', type=str, help='Path to the first role\'s yaml file')
parser.add_argument('second', metavar='SECOND', type=str, help='Path to the second role\'s yaml file')
parser.add_argument('--debug', dest='log_level', action='store_const', const=logging.DEBUG, default=logging.INFO, help='Print Z3 translation debug output')
args = parser.parse_args()

logging.basicConfig(level=args.log_level)

with (
  open(args.first, 'r') as r1,
  open(args.second, 'r') as r2
):
  try:
    r1 = yaml.safe_load(r1)
    r2 = yaml.safe_load(r2)
    test_equivalence(r1, r2)
  except yaml.YAMLError as e:
    print(e)
