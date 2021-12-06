from enum import Enum, auto
import logging
import re
import sre_parse
from z3 import *

# Helpers
def red(str):
  red_text_start = '\033[0;31m'
  red_text_end = '\033[00m'
  return red_text_start + str + red_text_end

# Z3 Node Constants
app_labels = Function('app_labels', StringSort(), StringSort())
app_label_keys = Function('app_label_keys', StringSort(), BoolSort())
node_labels = Function('node_labels', StringSort(), StringSort())
node_label_keys = Function('node_label_keys', StringSort(), BoolSort())
k8s_labels = Function('k8s_labels', StringSort(), StringSort())
k8s_label_keys = Function('k8s_label_keys', StringSort(), BoolSort())
db_labels = Function('db_labels', StringSort(), StringSort())
db_label_keys = Function('db_label_keys', StringSort(), BoolSort())
constraint_types = {
  'app_labels'        : (app_labels, app_label_keys),
  'node_labels'       : (node_labels, node_label_keys),
  'kubernetes_labels' : (k8s_labels, k8s_label_keys),
  'db_labels'         : (db_labels, db_label_keys)
}
class ConstraintType(Enum):
  APP = (app_labels, app_label_keys)
  NODE = (node_labels, node_label_keys)
  KUBERNETES = (k8s_labels, k8s_label_keys)
  DATABASE = (db_labels, db_label_keys)

# Z3 User Constants
internal_traits = Function(
  'internal_traits',
  StringSort(),
  StringSort(),
  BoolSort()
)
external_traits = Function(
  'external_traits',
  StringSort(),
  StringSort(),
  BoolSort()
)
template_types = {
  'internal'  : internal_traits,
  'external'  : external_traits
}
class UserType(Enum):
  INTERNAL = internal_traits
  EXTERNAL = external_traits

# Attempts to parse the given value as a regex.
# If the value is a valid regex, return (True, parsed_regex).
# If the value can just be treated as a normal string (example 'ababab')
# then return (False, None) so we can use regular string comparison.
# If the value is not a valid regex return (False, None).
def try_parse_regex(value):
  try:
    parsed_regex = sre_parse.parse(value)
    if not all([sre_parse.LITERAL == node_type for node_type, _ in parsed_regex]):
      return (True, parsed_regex)
    else:
      return (False, None)
  except Exception as e:
    logging.debug(f'Cannot parse regex {value} - {e}')
    return (False, None)

# Regex pattern for {{internal.logins}} or {{external.email}} type template values.
template_value_pattern = re.compile(r'\{\{(?P<type>internal|external)\.(?P<key>[\w]+)(\["(?P<inner_key>[\w]+)"\])?\}\}')

# Attempts to parse template constraints of type {{internal.logins}}
def try_parse_template(value):
  match = template_value_pattern.match(value)
  if None == match:
    return (False, None)
  
  user_type = match.group('type')
  trait_key = match.group('key')
  inner_trait_key = match.group('inner_key')

  return (True, (user_type, trait_key, inner_trait_key))

# Regex pattern for IAM#{{internal.logins}}#user type interpolation values.
interpolation_value_pattern = re.compile(r'(?P<prefix>.*)\{\{(?P<type>internal|external)\.(?P<key>[\w]+)(\["(?P<inner_key>[\w]+)"\])?\}\}(?P<suffix>.*)')

# Attempts to parse interpolation constraints of type IAM#{external.foo}
def try_parse_interpolation(value):
  match = interpolation_value_pattern.match(value)
  if None == match:
    return (False, None)
  
  prefix = match.group('prefix')
  user_type = match.group('type')
  trait_key = match.group('key')
  suffix = match.group('suffix')
  inner_trait_key = match.group('inner_key')

  return (True, (prefix, user_type, trait_key, inner_trait_key, suffix))

# Regex pattern for {{email.local(external.email)}}
email_function_value_pattern = re.compile(r'\{\{email\.local\([\s]*(?P<type>internal|external)\.(?P<key>[\w]+)(\["(?P<inner_key>[\w]+)"\])?[\s]*\)\}\}')

# Attempts to parse email function contraints of type {{email.local(external.email)}}
def try_parse_email_function(value):
  match = email_function_value_pattern.match(value)
  if None == match:
    return (False, None)

  user_type = match.group('type')
  trait_key = match.group('key')
  inner_trait_key = match.group('inner_key')

  return (True, (user_type, trait_key, inner_trait_key))

# Regex pattern for {{regexp.replace(external.access["env"], "^(staging)$", "$1")}}
regex_function_value_pattern = re.compile(r'\{\{regexp\.replace\([\s]*(?P<type>internal|external)\.(?P<key>[\w]+)(\["(?P<inner_key>[\w]+)"\])?[\s]*,[\s]*"(?P<pattern>.*)"[\s]*,[\s]*"(?P<replace>.*)"[\s]*\)\}\}')

# Attempts to parse regexp replace function constraints of type {{regexp.replace(external.access, "foo", "bar")}}
def try_parse_regexp_replace_function(value):
  match = regex_function_value_pattern.match(value)
  if None == match:
    return (False, None)

  user_type = match.group('type')
  trait_key = match.group('key')
  pattern = match.group('pattern')
  replace = match.group('replace')
  inner_trait_key = match.group('inner_key')

  return (True, (user_type, trait_key, inner_trait_key, pattern, replace))

# Determines whether the given constraint requires user traits to specify.
def requires_user_traits(values):
  if not isinstance(values, list):
    values = [values]
  for value in values:
    is_template, _ = try_parse_template(value)
    is_interpolation, _ = try_parse_interpolation(value)
    is_email_function, _ = try_parse_email_function(value)
    is_regexp_replace_function, _ = try_parse_regexp_replace_function(value)
    return is_template or is_interpolation or is_email_function or is_regexp_replace_function

# Possible types of constraint values.
class ValueType(Enum):
  MATCH_ANY = auto()
  STRING = auto()
  REGEX = auto()
  TEMPLATE = auto()
  INTERPOLATION = auto()
  EMAIL_FUNCTION = auto()
  REGEXP_REPLACE_FUNCTION = auto()

# Determines the category of the constraint value and parses it appropriately.
def parse_constraint(value):
  if '*' == value:
    return (ValueType.MATCH_ANY, value)
  
  is_template, parsed_value = try_parse_template(value)
  if is_template:
    return (ValueType.TEMPLATE, parsed_value)
  
  is_interpolation, parsed_value = try_parse_interpolation(value)
  if is_interpolation:
    return (ValueType.INTERPOLATION, parsed_value)
  
  is_email_function, parsed_value = try_parse_email_function(value)
  if is_email_function:
    return (ValueType.EMAIL_FUNCTION, parsed_value)

  is_regexp_replace_function, parsed_value = try_parse_regexp_replace_function(value)
  if is_regexp_replace_function:
    return (ValueType.REGEXP_REPLACE_FUNCTION, parsed_value)
  
  is_regex, parsed_regex = try_parse_regex(value)
  if is_regex:
    return (ValueType.REGEX, parsed_regex)
  
  return (ValueType.STRING, value)

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
# is satisfied by a given node, database, or k8s cluster.
# Example value for key : value parameters:
#
# 'location' : 'us-east-[\d]+'
# 'owner' : {{external.email}}
#
def matches_value(labels, key, value):
  constraint_type, parsed_value = parse_constraint(value)
  # 'key' : '*'
  if ValueType.MATCH_ANY == constraint_type:
    return BoolVal(True)
  # 'key' : 'value'
  elif ValueType.STRING == constraint_type:
    return labels(key) == StringVal(parsed_value)
  # 'key' : '(ab)*a
  elif ValueType.REGEX == constraint_type:
    logging.debug(f'Uncompiled regex {parsed_value}')
    regex = regex_to_z3_expr(parsed_value)
    logging.debug(f'Compiled regex {regex}')
    return InRe(labels(key), regex)
  # 'key' : '{internal.trait_key}'
  elif ValueType.TEMPLATE == constraint_type:
    user_trait_type, user_trait_key, inner_trait_key = parsed_value
    logging.debug(f'User trait constraint of type {user_trait_type} on key {user_trait_key}[{inner_trait_key}]')
    if None != inner_trait_key:
      quit(red(f'Nested trait maps are not supported: {value}'))
    user_trait_type = template_types[user_trait_type]
    user_trait_key = StringVal(user_trait_key)
    return user_trait_type(user_trait_key, labels(key))
  # 'key' : 'prefix#{internal.trait_key}#suffix'
  elif ValueType.INTERPOLATION == constraint_type:
    prefix, user_trait_type, user_trait_key, inner_trait_key, suffix = parsed_value
    logging.debug(f'User interpolation constraint of type {user_trait_type} on key {user_trait_key}[{inner_trait_key}] with prefix {prefix} and suffix {suffix}')
    if None != inner_trait_key:
      quit(red(f'Nested trait maps are not supported: {value}'))
    prefix = StringVal(prefix)
    suffix = StringVal(suffix)
    user_trait_type = template_types[user_trait_type]
    user_trait_key = StringVal(user_trait_key)
    user_trait_value = String(f'{user_trait_type}_{user_trait_key}')
    expr = user_trait_type(user_trait_key, user_trait_value)
    expr = And(expr, labels(key) == Concat(prefix, user_trait_value, suffix))
    return Exists(user_trait_value, expr)
  # 'key' : '{{email.local(external.email)}}'
  elif ValueType.EMAIL_FUNCTION == constraint_type:
    user_trait_type, user_trait_key, inner_trait_key = parsed_value
    logging.debug(f'Email function constraint of type {user_trait_type} on key {user_trait_key}[{inner_trait_key}]')
    if None != inner_trait_key:
      quit(red(f'Nested trait maps are not supported: {value}'))
    user_trait_type = template_types[user_trait_type]
    user_trait_key = StringVal(user_trait_key)
    user_trait_value = String(f'{user_trait_type}_{user_trait_key}_email')
    expr = user_trait_type(user_trait_key, user_trait_value)
    expr = And(expr, labels(key) == SubString(user_trait_value, IntVal(0), IndexOf(user_trait_value, StringVal('@')) + IntVal(1)))
    return Exists(user_trait_value, expr)
  elif ValueType.REGEXP_REPLACE_FUNCTION == constraint_type:
    user_trait_type, user_trait_key, inner_trait_key, pattern, replace = parsed_value
    logging.debug(f'Regexp replace function constraint of type {user_trait_type} on key {user_trait_key}[{inner_trait_key}], replacing {pattern} with {replace}')
    quit(red(f'Regexp replace function constraint not yet supported given {key} : {value}'))
  else:
    quit(red(f'Unknown constraint value type {value}; not supported.'))

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
      return BoolVal(True)
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
def matches_constraints(constraint_type, labels, label_keys, constraints):
  logging.debug(f'Compiling {constraint_type} constraints')
  return And([
    And(matches_constraint(labels, key, value), label_keys(StringVal(key)))
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
    and matches_constraints(constraint_type, labels, label_keys, group[constraint_type])
    for constraint_type, (labels, label_keys) in constraint_types.items()
  ])

# Constructs an expression evaluating to whether a given role
# gives access to a specific node, database, or k8s cluster.
# Example value for role parameter:
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
def allows(role):
  role_name = role['metadata']['name']
  logging.debug(f'Compiling role template {role_name}')
  spec = role['spec']
  logging.debug('Compiling allow constraints')
  allow_expr = 'allow' in spec and matches_constraint_group(spec['allow'])
  logging.debug('Compiling deny constraints')
  deny_expr = 'deny' in spec and matches_constraint_group(spec['deny'])
  return And(allow_expr, Not(deny_expr))

# Determines whether the given role is a role template, filled in by user traits.
def is_role_template(role):
  spec = role['spec']
  if 'allow' in spec:
    allow = spec['allow']
    groups = [allow[constraint_type].values() for constraint_type in constraint_types.keys() if constraint_type in allow]
    if any([requires_user_traits(value) for values in groups for value in values]):
      return True

  if 'deny' in spec:
    deny = spec['deny']
    groups = [deny[constraint_type] for constraint_type in constraint_types.keys() if constraint_type in deny]
    if any([requires_user_traits(value) for values in groups for value in values]):
      return True

  return False

# Compiles the labels of a given node, k8s cluster, or database into a
# form understood by Z3 that can be checked against a compiled set of role
# constraints.
def labels_as_z3_map(labels, constraint_type):
  logging.debug(f'Compiling labels {labels} of type {constraint_type.name}')
  labels, label_keys = constraint_type.value
  return And([And(labels(StringVal(key)) == StringVal(value), label_keys(StringVal(key))) for key, value in labels.items()])

# Compiles the traits of a given internal or external user into a form
# understood by Z3 that can be checked against a compiled set of role constraints.
def traits_as_z3_map(traits, user_type):
  logging.debug(f'Compiling user traits {traits} of type {user_type.name}')
  if UserType.INTERNAL == user_type:
    return And([user_type.value(StringVal(key), (StringVal(value))) for key, values in traits.items() for value in values])
  