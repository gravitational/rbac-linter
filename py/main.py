import yaml
from z3 import *

def analyze(role_template):
  s = Solver()
  x = String('x')
  ab = Loop(Re('ab'), 1, 3)
  s.add(InRe(x, ab), Length(x) == 6)
  print(s.check())
  print(s.model())

with open('../data/role.yml', 'r') as role_template_file:
  try:
    role_template = yaml.safe_load(role_template_file)
    analyze(role_template)
  except yaml.YAMLError as e:
    print(e)
