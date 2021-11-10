import logging
from role_analyzer import allows
import yaml
from z3 import *

logging.basicConfig(level=logging.DEBUG)

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

with (
  open('data/role.yml', 'r') as r1,
  open('data/role2.yml', 'r') as r2
):
  try:
    r1 = yaml.safe_load(r1)
    r2 = yaml.safe_load(r2)
    test_equivalence(r1, r2)
  except yaml.YAMLError as e:
    print(e)
