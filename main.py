import yaml
from z3 import *
import sre_parse

# Constants
node_labels = Array('node_labels', StringSort(), StringSort())
kubernetes_labels = Array('kubernetes_labels', StringSort(), StringSort())
database_labels = Array('database_labels', StringSort(), StringSort())

# Datatypes
kv = Datatype('kv')
kv.declare('kv', ('key', StringSort()), ('value', StringSort()))
kv = kv.create()
#kv1 = kv.kv(StringVal('foo'), StringVal('bar'))

def is_regex(parsed_regex):
  return not all([sre_parse.LITERAL == node_type for node_type, _ in parsed_regex])

def regex_construct_to_z3_expr(regex_construct):
  node_type, node_value = regex_construct
  if sre_parse.LITERAL == node_type: # a
    return Re(chr(node_value))
  elif sre_parse.ANY == node_type: # .
    quit('Regex construct . not yet implemented')
  elif sre_parse.MAX_REPEAT == node_type:
    low, high, value = node_value
    if (0, 1) == (low, high): # a?
      return Option(regex_to_z3_expr(value))
    elif (0, sre_parse.MAXREPEAT) == (low, high): # a*
      return Star(regex_to_z3_expr(value))
    elif (1, sre_parse.MAXREPEAT) == (low, high): # a+
      return Plus(regex_to_z3_expr(value))
    else: # a{3,5}, a{3}
      return Loop(low, high, regex_to_z3_expr(value))
  elif sre_parse.IN == node_type: # [abc]
    return Union([regex_to_z3_expr(value) for value in node_value])
  elif sre_parse.BRANCH == node_type: # ab|cd
    return Union([regex_to_z3_expr(value) for _, value in node_value])
  elif sre_parse.RANGE == node_type: # [a-z]
    low, high = node_value
    return Range(chr(low), chr(high))
  else:
    quit('Regex construct ' + regex_construct + ' not yet implemented')

def regex_to_z3_expr(regex):
  print(f'Regex {regex}')
  if 0 == len(regex):
    quit('ERROR: regex is empty')
  if 1 == len(regex):
    return regex_construct_to_z3_expr(regex[0])
  else:
    return Concat([regex_construct_to_z3_expr(construct) for construct in regex])

def matches_value(labels, key, value):
  print(f'Constraint {key} : {value}')
  parsed_regex = sre_parse.parse(value)
  if is_regex(parsed_regex):
    return InRe(Select(labels, key), regex_to_z3_expr(parsed_regex))
  else:
    return Select(labels, key) == StringVal(value)

def matches_constraints(labels, constraints):
  if '*' in constraints and constraints['*'] == '*':
    return True

  match_expr = False
  for key, value in constraints.items():
    key = StringVal(key)
    if isinstance(value, list):
      list_expr = False
      for v in value:
        list_expr = Or(list_expr, matches_value(labels, key, v))
      match_expr = Or(match_expr, list_expr)
    else:
      match_expr = Or(match_expr, matches_value(labels, key, value))

  return match_expr

def matches_constraint_group(group):
  constraint_types = {
    'node_labels'       : node_labels,
    'kubernetes_labels' : kubernetes_labels,
    'database_labels'   : database_labels
  }

  match_expr = False
  for constraint, labels in constraint_types.items():
    match = constraint in group and matches_constraints(labels, group[constraint])
    match_expr = Or(match_expr, match)

  return match_expr

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
