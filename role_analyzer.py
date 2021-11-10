import logging
import sre_parse
from z3 import *

# Constants
node_labels = Function('node_labels', StringSort(), StringSort())
kubernetes_labels = Function('kubernetes_labels', StringSort(), StringSort())
database_labels = Function('database_labels', StringSort(), StringSort())

# Datatypes
kv = Datatype('kv')
kv.declare('kv', ('key', StringSort()), ('value', StringSort()))
kv = kv.create()
#kv1 = kv.kv(StringVal('foo'), StringVal('bar'))

# Tests whether the given regex can just be treated as a string.
# For example, we can use normal string comparison for 'ababab' instead of
# the presumably less-efficient regular expression solver.
def is_regex(parsed_regex):
  return not all([sre_parse.LITERAL == node_type for node_type, _ in parsed_regex])

# Translates a specific regex construct into its Z3 equivalent.
def regex_construct_to_z3_expr(regex_construct):
  node_type, node_value = regex_construct
  if sre_parse.LITERAL == node_type: # a
    return Re(chr(node_value))
  if sre_parse.SUBPATTERN == node_type:
    _, _, _, value = node_value
    return regex_to_z3_expr(value)
  elif sre_parse.ANY == node_type: # .
    return Range(chr(0), chr(127)) # Support ASCII for now
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
    quit(f'Regex construct {regex_construct} not yet implemented')

# Translates a parsed regex into its Z3 equivalent.
# The parsed regex is a sequence of regex constructs (literals, *, +, etc.)
def regex_to_z3_expr(regex):
  logging.debug(f'Regex {regex}')
  if 0 == len(regex):
    quit('ERROR: regex is empty')
  elif 1 == len(regex):
    return regex_construct_to_z3_expr(regex[0])
  else:
    expr = Concat([regex_construct_to_z3_expr(construct) for construct in regex])
    logging.debug(expr)
    return expr

# Constructs an expression evaluating whether a specific label constraint
# is satisfied by a given node, database, or k8s cluster; constraint must
# be either a concrete string value or a regex.
# Example value for key : value parameters:
#
# 'location' : 'us-east-[\d]+'
#
def matches_value(labels, key, value):
  logging.debug(f'Constraint {key} : {value}')
  if '*' == value:
    return True

  parsed_regex = sre_parse.parse(value)
  if is_regex(parsed_regex):
    return InRe(labels(key), regex_to_z3_expr(parsed_regex))
  else:
    return labels(key) == StringVal(value)

# Constructs an expression evaluating whether a specific label constraint
# is satisfied by a given node, database, or k8s cluster; constraint can
# take the form of a list of permissible values.
# Example value for key : value parameters:
#
# 'env' : ['test', 'prod']
#
def matches_constraint(labels, key, value):
  logging.debug(f'Constraint {key} : {value}')
  if '*' == key:
    if '*' == value:
      return True
    else:
      quit(f'Constraint of type \'*\' : {value} not supported')

  key = StringVal(key)
  if isinstance(value, list):
    return Or([matches_value(labels, key, v) for v in value])
  else:
    return matches_value(labels, key, value)
  

# Constructs an expression evaluating to whether a given set of label
# requirements are satisfied by a given node, database, or k8s cluster.
# Example value for constraints parameter:
#
# {'env' : ['test', 'prod'], 'location' : 'us-east-[\d]+' }
#
def matches_constraints(labels, constraints):
  return And([
    matches_constraint(labels, key, value)
    for key, value in constraints.items()
  ])

# Constructs an expression evaluating to whether a given constraint group
# (either Allow or Deny) matches the labels of a given node, database, or
# k8s cluster.
# Example value for group parameter:
#
# node_labels:
#   'env' : 'test'
#   'owner' : '.*@email.com'
# database_labels:
#   'contains_PII' : 'no'
#
def matches_constraint_group(group):
  constraint_types = {
    'node_labels'       : node_labels,
    'kubernetes_labels' : kubernetes_labels,
    'database_labels'   : database_labels
  }

  return Or([
    constraint_type in group and matches_constraints(labels, group[constraint_type])
    for constraint_type, labels in constraint_types.items()
  ])

# Constructs an expression evaluating to whether a given role template
# gives access to a specific node, database, or k8s cluster.
# Example value for role_template parameter:
#
# spec:
#  allow:
#    node_labels:
#      'env' : 'test'
#    kubernetes_labels:
#      'service' : 'company_app'
#  deny:
#    node_labels:
#      'env' : 'prod'
#
def allows(role_template):
  spec = role_template['spec']
  allow_expr = 'allow' in spec and matches_constraint_group(spec['allow'])
  deny_expr = 'deny' in spec and matches_constraint_group(spec['deny'])
  return And(allow_expr, Not(deny_expr))

def labels_as_map(labels):
  print(labels.items())
  print([(key, value) for key, value in labels.items()])
  return And([node_labels(StringVal(key)) == value for key, value in labels.items()])
