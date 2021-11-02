import yaml
from z3 import *

# Datatypes
node_labels = Array('node_labels', StringSort(), StringSort())

kv = Datatype('kv')
kv.declare('kv', ('key', StringSort()), ('value', StringSort()))
kv = kv.create()
#kv1 = kv.kv(StringVal('foo'), StringVal('bar'))

def matches_constraints(labels, constraints):
  match_expr = True
  for key, value in constraints.items():
    key = StringVal(key)
    if isinstance(value, list):
      list_expr = False
      for v in value:
        list_expr = Or(list_expr, Select(labels, key) == StringVal(v))
      match_expr = And(match_expr, list_expr)
    else:
      match_expr = And(match_expr, Select(labels, key) == StringVal(value))

  return match_expr

  #x = String('x')
  #ab = Star(Re('ab'))
  #s.add(InRe(x, ab), Length(x) == 6)

def matches_constraint_group(group):
  match_node_labels = 'node_labels' in group and matches_constraints(node_labels, group['node_labels'])
  return match_node_labels

def allows(role_template):
  spec = role_template['spec']
  allow_expr = 'allow' in spec and matches_constraint_group(spec['allow'])
  deny_expr = 'deny' in spec and matches_constraint_group(spec['deny'])
  return And(allow_expr, Not(deny_expr))

def test_equivalence(r1, r2):
  r1 = allows(r1)
  r2 = allows(r2)
  s = Solver()
  s.add(Not(r1 == r2))
  result = s.check()
  print(result)
  if sat == result:
    print(s.model())

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
