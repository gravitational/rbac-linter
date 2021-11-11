import logging
from role_analyzer import allows, labels_as_z3_map, ConstraintType
import yaml
from z3 import *

logging.basicConfig(level=logging.DEBUG)

def test_matches_node(role):
  labels = {
    'env' : 'd'
  }
  
  s = Solver()
  s.add(labels_as_z3_map(labels, ConstraintType.NODE))
  s.check()
  result = s.model().evaluate(allows(role), model_completion=True)
  if result:
    print('The role matches the given node.')
  else:
    print('The role does not match the given node.')

with (open('data/role.yml', 'r') as role):
  try:
    role = yaml.safe_load(role)
    test_matches_node(role)
  except yaml.YAMLError as e:
    print(e)
