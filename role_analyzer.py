from enum import Enum
import logging
import sre_parse
from z3 import *

# Helpers
def red(str):
  red_text_start = '\033[0;31m'
  red_text_end = '\033[00m'
  return red_text_start + str + red_text_end

# Z3 Constants
node_labels = Function('node_labels', StringSort(), StringSort())
kubernetes_labels = Function('kubernetes_labels', StringSort(), StringSort())
database_labels = Function('database_labels', StringSort(), StringSort())
constraint_types = {
  'node_labels'       : node_labels,
  'kubernetes_labels' : kubernetes_labels,
  'database_labels'   : database_labels
}

# The three types of constraints and their corresponding Z3 constant functions.
class ConstraintType(Enum):
  NODE = node_labels
  KUBERNETES = kubernetes_labels
  DATABASE = database_labels

# Tests whether the given regex can just be treated as a string.
# For example, we can use normal string comparison for 'ababab' instead of
# the presumably less-efficient regular expression solver.
def is_regex(parsed_regex):
  return not all([sre_parse.LITERAL == node_type for node_type, _ in parsed_regex])

# The Z3 regex matching all strings accepted by re1 but not re2.
# Formatted in camelcase to mimic Z3 regex API.
def Minus(re1, re2):
  return Intersect(re1, Complement(re2))

# The Z3 regex matching any ASCII character.
# Formatted in camelcase to mimic Z3 regex API.
def AnyAsciiChar():
  return Range(chr(0), chr(127))

# Defines regex categories in Z3.
def category_regex(category):
  if sre_parse.CATEGORY_DIGIT == category:
    return Range('0', '9')
  elif sre_parse.CATEGORY_SPACE == category:
    return Union(Re(' '), Re('\t'), Re('\n'), Re('\r'), Re('\f'), Re('\v'))
  elif sre_parse.CATEGORY_WORD == category:
    return Union(Range('a', 'z'), Range('A', 'Z'), Range('0', '9'), Re('_'))
  else:
    quit(red(f'ERROR: regex category {category} not yet implemented'))
    
# Translates a specific regex construct into its Z3 equivalent.
def regex_construct_to_z3_expr(regex_construct):
  node_type, node_value = regex_construct
  if sre_parse.LITERAL == node_type: # a
    return Re(chr(node_value))
  if sre_parse.NOT_LITERAL == node_type: # [^a]
    return Minus(AnyAsciiChar(), Re(chr(node_value)))
  if sre_parse.SUBPATTERN == node_type:
    _, _, _, value = node_value
    return regex_to_z3_expr(value)
  elif sre_parse.ANY == node_type: # .
    return AnyAsciiChar()
  elif sre_parse.MAX_REPEAT == node_type:
    low, high, value = node_value
    if (0, 1) == (low, high): # a?
      return Option(regex_to_z3_expr(value))
    elif (0, sre_parse.MAXREPEAT) == (low, high): # a*
      return Star(regex_to_z3_expr(value))
    elif (1, sre_parse.MAXREPEAT) == (low, high): # a+
      return Plus(regex_to_z3_expr(value))
    else: # a{3,5}, a{3}
      return Loop(regex_to_z3_expr(value), low, high)
  elif sre_parse.IN == node_type: # [abc]
    first_subnode_type, _ = node_value[0]
    if sre_parse.NEGATE == first_subnode_type: # [^abc]
      return Minus(AnyAsciiChar(), Union([regex_construct_to_z3_expr(value) for value in node_value[1:]]))
    else:
      return Union([regex_construct_to_z3_expr(value) for value in node_value])
  elif sre_parse.BRANCH == node_type: # ab|cd
    _, value = node_value
    return Union([regex_to_z3_expr(v) for v in value])
  elif sre_parse.RANGE == node_type: # [a-z]
    low, high = node_value
    return Range(chr(low), chr(high))
  elif sre_parse.CATEGORY == node_type: # \d, \s, \w
    if sre_parse.CATEGORY_DIGIT == node_value: # \d
      return category_regex(node_value)
    elif sre_parse.CATEGORY_NOT_DIGIT == node_value: # \D
      return Minus(AnyAsciiChar(), category_regex(sre_parse.CATEGORY_DIGIT))
    elif sre_parse.CATEGORY_SPACE == node_value: # \s
      return category_regex(node_value)
    elif sre_parse.CATEGORY_NOT_SPACE == node_value: # \S
      return Minus(AnyAsciiChar(), category_regex(sre_parse.CATEGORY_SPACE))
    elif sre_parse.CATEGORY_WORD == node_value: # \w
      return category_regex(node_value)
    elif sre_parse.CATEGORY_NOT_WORD == node_value: # \W
      return Minus(AnyAsciiChar(), category_regex(sre_parse.CATEGORY_WORD))
    else:
      quit(red(f'ERROR: regex category {node_value} not implemented'))
  elif sre_parse.AT == node_type:
    if node_value in {sre_parse.AT_BEGINNING, sre_parse.AT_BEGINNING_STRING}: # ^a, \A
      quit(red(f'ERROR: regex position {node_value} not implemented'))
    elif sre_parse.AT_BOUNDARY == node_value: # \b
      quit(red(f'ERROR: regex position {node_value} not implemented'))
    elif sre_parse.AT_NON_BOUNDARY == node_value: # \B
      quit(red(f'ERROR: regex position {node_value} not implemented'))
    elif node_value in {sre_parse.AT_END, sre_parse.AT_END_STRING}: # a$, \Z
      quit(red(f'ERROR: regex position {node_value} not implemented'))
    else:
      quit(red(f'ERROR: regex position {node_value} not implemented'))
  else:
    quit(red(f'ERROR: regex construct {regex_construct} not implemented'))

# Translates a parsed regex into its Z3 equivalent.
# The parsed regex is a sequence of regex constructs (literals, *, +, etc.)
def regex_to_z3_expr(regex):
  if 0 == len(regex):
    quit(red('ERROR: regex is empty'))
  elif 1 == len(regex):
    return regex_construct_to_z3_expr(regex[0])
  else:
    return Concat([regex_construct_to_z3_expr(construct) for construct in regex])

# Constructs an expression evaluating whether a specific label constraint
# is satisfied by a given node, database, or k8s cluster; constraint must
# be either a concrete string value or a regex.
# Example value for key : value parameters:
#
# 'location' : 'us-east-[\d]+'
#
def matches_value(labels, key, value):
  if '*' == value:
    return True

  try:
    parsed_regex = sre_parse.parse(value)
  except Exception as e:
    quit(red(f'ERROR: cannot parse regex {value} - {e}'))

  if is_regex(parsed_regex):
    logging.debug(f'Uncompiled regex {parsed_regex}')
    regex = regex_to_z3_expr(parsed_regex)
    logging.debug(f'Compiled regex {regex}')
    return InRe(labels(key), regex)
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
  logging.debug(f'Compiling {key} : {value} constraint')
  if '*' == key:
    if '*' == value:
      return True
    else:
      quit(red(f'Constraint of type \'*\' : {value} not supported'))

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
def matches_constraints(constraint_type, labels, constraints):
  logging.debug(f'Compiling {constraint_type} constraints')
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
  return Or([
    constraint_type in group
    and matches_constraints(constraint_type, labels, group[constraint_type])
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
  role_name = role_template['metadata']['name']
  logging.debug(f'Compiling role template {role_name}')
  spec = role_template['spec']
  logging.debug('Compiling allow constraints')
  allow_expr = 'allow' in spec and matches_constraint_group(spec['allow'])
  logging.debug('Compiling deny constraints')
  deny_expr = 'deny' in spec and matches_constraint_group(spec['deny'])
  return And(allow_expr, Not(deny_expr))

# Compiles the labels of a given node, k8s cluster, or database into a
# form understood by Z3 that can be checked against a compiled set of role
# constraints.
def labels_as_z3_map(labels, constraint_type):
  logging.debug(f'Compiling labels {labels} of type {constraint_type.name}')
  return And([constraint_type.value(StringVal(key)) == value for key, value in labels.items()])
