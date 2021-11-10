import logging
from role_analyzer import allows, labels_as_map
import yaml
from z3 import *

logging.basicConfig(level=logging.DEBUG)

def test_matches_node(role):
  labels = {
    'env' : 'aaaaaaaaaaaaaaa',
  }
  
  s = Solver()
  s.add(labels_as_map(labels))
  s.check()
  print(s.model().eval(allows(role)))

with (open('data/role.yml', 'r') as role):
  try:
    role = yaml.safe_load(role)
    test_matches_node(role)
  except yaml.YAMLError as e:
    print(e)
