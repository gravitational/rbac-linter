from dataclasses import dataclass
from enum import Enum
import logging
import re
import sre_constants
import sre_parse
import typing
import z3 # type: ignore

# Z3 Node Constants
app_labels      = z3.Function('app_labels',       z3.StringSort(),  z3.StringSort())
app_label_keys  = z3.Function('app_label_keys',   z3.StringSort(),  z3.BoolSort())
node_labels     = z3.Function('node_labels',      z3.StringSort(),  z3.StringSort())
node_label_keys = z3.Function('node_label_keys',  z3.StringSort(),  z3.BoolSort())
k8s_labels      = z3.Function('k8s_labels',       z3.StringSort(),  z3.StringSort())
k8s_label_keys  = z3.Function('k8s_label_keys',   z3.StringSort(),  z3.BoolSort())
db_labels       = z3.Function('db_labels',        z3.StringSort(),  z3.StringSort())
db_label_keys   = z3.Function('db_label_keys',    z3.StringSort(),  z3.BoolSort())
entity_types = {
  'app_labels'        : (app_labels,  app_label_keys),
  'node_labels'       : (node_labels, node_label_keys),
  'kubernetes_labels' : (k8s_labels,  k8s_label_keys),
  'db_labels'         : (db_labels,   db_label_keys)
}
class EntityType(Enum):
  APP   = (app_labels,  app_label_keys)
  NODE  = (node_labels, node_label_keys)
  K8S   = (k8s_labels,  k8s_label_keys)
  DB    = (db_labels,   db_label_keys)

# Z3 User Constants
internal_traits = z3.Function(
  'internal_traits',
  z3.StringSort(),
  z3.StringSort(),
  z3.BoolSort()
)
external_traits = z3.Function(
  'external_traits',
  z3.StringSort(),
  z3.StringSort(),
  z3.BoolSort()
)
template_types = {
  'internal'  : internal_traits,
  'external'  : external_traits
}
class UserType(Enum):
  INTERNAL = internal_traits
  EXTERNAL = external_traits

@dataclass
class AnyValueConstraint:
  value : str

@dataclass
class StringConstraint:
  value : str

@dataclass
class RegexConstraint:
  regex : sre_parse.SubPattern

@dataclass
class UserTraitConstraint:
  trait_type      : str
  trait_key       : str
  inner_trait_key : str

@dataclass
class InterpolationConstraint:
  prefix          : str
  trait_type      : str
  trait_key       : str
  inner_trait_key : str
  suffix          : str

@dataclass
class EmailFunctionConstraint:
  trait_type      : str
  trait_key       : str
  inner_trait_key : str

@dataclass
class RegexReplaceFunctionConstraint:
  trait_type      : str
  trait_key       : str
  inner_trait_key : str
  pattern         : str
  replace         : str

# Attempts to parse the given value as a regex.
def try_parse_regex(value : str) -> typing.Optional[RegexConstraint]:
  try:
    parsed_regex = sre_parse.parse(value)
    is_regex = not all([
      sre_constants.LITERAL == node_type
      for node_type, _ in parsed_regex.data
    ])
    return RegexConstraint(parsed_regex) if is_regex else None
  except Exception as e:
    logging.debug(f'Cannot parse regex {value} - {e}')
    return None

# Regex pattern for {{internal.logins}} or {{external.email}} type template values.
template_value_pattern = re.compile(r'\{\{(?P<type>internal|external)\.(?P<key>[\w]+)(\["(?P<inner_key>[\w]+)"\])?\}\}')

# Attempts to parse template constraints of type {{internal.logins}}
def try_parse_template(value : str) -> typing.Optional[UserTraitConstraint]:
  match = template_value_pattern.match(value)
  if isinstance(match, re.Match):
    user_type = match.group('type')
    trait_key = match.group('key')
    inner_trait_key = match.group('inner_key')
    return UserTraitConstraint(user_type, trait_key, inner_trait_key)
  else:
    return None

# Regex pattern for IAM#{{internal.logins}}#user type interpolation values.
interpolation_value_pattern = re.compile(r'(?P<prefix>.*)\{\{(?P<type>internal|external)\.(?P<key>[\w]+)(\["(?P<inner_key>[\w]+)"\])?\}\}(?P<suffix>.*)')

# Attempts to parse interpolation constraints of type IAM#{external.foo}
def try_parse_interpolation(value : str) -> typing.Optional[InterpolationConstraint]:
  match = interpolation_value_pattern.match(value)
  if isinstance(match, re.Match):
    prefix = match.group('prefix')
    user_type = match.group('type')
    trait_key = match.group('key')
    inner_trait_key = match.group('inner_key')
    suffix = match.group('suffix')
    return InterpolationConstraint(prefix, user_type, trait_key, inner_trait_key, suffix)
  else:
    return None

# Regex pattern for {{email.local(external.email)}}
email_function_value_pattern = re.compile(r'\{\{email\.local\([\s]*(?P<type>internal|external)\.(?P<key>[\w]+)(\["(?P<inner_key>[\w]+)"\])?[\s]*\)\}\}')

# Attempts to parse email function contraints of type {{email.local(external.email)}}
def try_parse_email_function(value : str) -> typing.Optional[EmailFunctionConstraint]:
  match = email_function_value_pattern.match(value)
  if isinstance(match, re.Match):
    user_type = match.group('type')
    trait_key = match.group('key')
    inner_trait_key = match.group('inner_key')
    return EmailFunctionConstraint(user_type, trait_key, inner_trait_key)
  else:
    return None

# Regex pattern for {{regexp.replace(external.access["env"], "^(staging)$", "$1")}}
regex_function_value_pattern = re.compile(r'\{\{regexp\.replace\([\s]*(?P<type>internal|external)\.(?P<key>[\w]+)(\["(?P<inner_key>[\w]+)"\])?[\s]*,[\s]*"(?P<pattern>.*)"[\s]*,[\s]*"(?P<replace>.*)"[\s]*\)\}\}')

# Attempts to parse regexp replace function constraints of type {{regexp.replace(external.access, "foo", "bar")}}
def try_parse_regexp_replace_function(value : str) -> typing.Optional[RegexReplaceFunctionConstraint]:
  match = regex_function_value_pattern.match(value)
  if isinstance(match, re.Match):
    user_type = match.group('type')
    trait_key = match.group('key')
    inner_trait_key = match.group('inner_key')
    pattern = match.group('pattern')
    replace = match.group('replace')
    return RegexReplaceFunctionConstraint(user_type, trait_key, inner_trait_key, pattern, replace)
  else:
    return None

# Determines whether the given constraint requires user traits to specify.
def requires_user_traits(values : typing.Union[str, list[str]]) -> bool:
  if not isinstance(values, list):
    values = [values]
  for value in values:
    is_template = try_parse_template(value) != None
    is_interpolation = try_parse_interpolation(value) != None
    is_email_function = try_parse_email_function(value) != None
    is_regexp_replace_function = try_parse_regexp_replace_function(value) != None
    if is_template or is_interpolation or is_email_function or is_regexp_replace_function:
      return True
  return False

# Determines the category of the constraint value and parses it appropriately.
def parse_constraint(
    value : str
  ) -> typing.Union[
    AnyValueConstraint,
    StringConstraint,
    RegexConstraint,
    UserTraitConstraint,
    InterpolationConstraint,
    EmailFunctionConstraint,
    RegexReplaceFunctionConstraint]:

  if '*' == value:
    return AnyValueConstraint(value)
  
  parsed_trait_constraint = try_parse_template(value)
  if isinstance(parsed_trait_constraint, UserTraitConstraint):
    return parsed_trait_constraint
  
  parsed_interpolation_constraint = try_parse_interpolation(value)
  if isinstance(parsed_interpolation_constraint, InterpolationConstraint):
    return parsed_interpolation_constraint
  
  parsed_email_constraint = try_parse_email_function(value)
  if isinstance(parsed_email_constraint, EmailFunctionConstraint):
    return parsed_email_constraint

  parsed_regex_function_constraint = try_parse_regexp_replace_function(value)
  if isinstance(parsed_regex_function_constraint, RegexReplaceFunctionConstraint):
    return parsed_regex_function_constraint
  
  parsed_regex_constraint = try_parse_regex(value)
  if isinstance(parsed_regex_constraint, RegexConstraint):
    return parsed_regex_constraint
  
  return StringConstraint(value)

# The Z3 regex matching all strings accepted by re1 but not re2.
# Formatted in camelcase to mimic Z3 regex API.
def Minus(re1 : z3.ReRef, re2 : z3.ReRef) -> z3.ReRef:
  return z3.Intersect(re1, z3.Complement(re2))

# The Z3 regex matching any character (currently only ASCII supported).
# Formatted in camelcase to mimic Z3 regex API.
def AnyChar() -> z3.ReRef:
  return z3.Range(chr(0), chr(127))
  #return z3.AllChar(z3.StringSort())

# Defines regex categories in Z3.
def category_regex(category : sre_constants._NamedIntConstant) -> z3.ReRef:
  if sre_constants.CATEGORY_DIGIT == category:
    return z3.Range('0', '9')
  elif sre_constants.CATEGORY_SPACE == category:
    return z3.Union(z3.Re(' '), z3.Re('\t'), z3.Re('\n'), z3.Re('\r'), z3.Re('\f'), z3.Re('\v'))
  elif sre_constants.CATEGORY_WORD == category:
    return z3.Union(z3.Range('a', 'z'), z3.Range('A', 'Z'), z3.Range('0', '9'), z3.Re('_'))
  else:
    raise NotImplementedError(f'ERROR: regex category {category} not yet implemented')
    
# Translates a specific regex construct into its Z3 equivalent.
def regex_construct_to_z3_expr(regex_construct) -> z3.ReRef:
  node_type, node_value = regex_construct
  if sre_constants.LITERAL == node_type: # a
    return z3.Re(chr(node_value))
  if sre_constants.NOT_LITERAL == node_type: # [^a]
    return Minus(AnyChar(), z3.Re(chr(node_value)))
  if sre_constants.SUBPATTERN == node_type:
    _, _, _, value = node_value
    return regex_to_z3_expr(value)
  elif sre_constants.ANY == node_type: # .
    return AnyChar()
  elif sre_constants.MAX_REPEAT == node_type:
    low, high, value = node_value
    if (0, 1) == (low, high): # a?
      return z3.Option(regex_to_z3_expr(value))
    elif (0, sre_constants.MAXREPEAT) == (low, high): # a*
      return z3.Star(regex_to_z3_expr(value))
    elif (1, sre_constants.MAXREPEAT) == (low, high): # a+
      return z3.Plus(regex_to_z3_expr(value))
    else: # a{3,5}, a{3}
      return z3.Loop(regex_to_z3_expr(value), low, high)
  elif sre_constants.IN == node_type: # [abc]
    first_subnode_type, _ = node_value[0]
    if sre_constants.NEGATE == first_subnode_type: # [^abc]
      return Minus(AnyChar(), z3.Union([regex_construct_to_z3_expr(value) for value in node_value[1:]]))
    else:
      return z3.Union([regex_construct_to_z3_expr(value) for value in node_value])
  elif sre_constants.BRANCH == node_type: # ab|cd
    _, value = node_value
    return z3.Union([regex_to_z3_expr(v) for v in value])
  elif sre_constants.RANGE == node_type: # [a-z]
    low, high = node_value
    return z3.Range(chr(low), chr(high))
  elif sre_constants.CATEGORY == node_type: # \d, \s, \w
    if sre_constants.CATEGORY_DIGIT == node_value: # \d
      return category_regex(node_value)
    elif sre_constants.CATEGORY_NOT_DIGIT == node_value: # \D
      return Minus(AnyChar(), category_regex(sre_constants.CATEGORY_DIGIT))
    elif sre_constants.CATEGORY_SPACE == node_value: # \s
      return category_regex(node_value)
    elif sre_constants.CATEGORY_NOT_SPACE == node_value: # \S
      return Minus(AnyChar(), category_regex(sre_constants.CATEGORY_SPACE))
    elif sre_constants.CATEGORY_WORD == node_value: # \w
      return category_regex(node_value)
    elif sre_constants.CATEGORY_NOT_WORD == node_value: # \W
      return Minus(AnyChar(), category_regex(sre_constants.CATEGORY_WORD))
    else:
      raise NotImplementedError(f'ERROR: regex category {node_value} not implemented')
  elif sre_constants.AT == node_type:
    if node_value in {sre_constants.AT_BEGINNING, sre_constants.AT_BEGINNING_STRING}: # ^a, \A
      raise NotImplementedError(f'ERROR: regex position {node_value} not implemented')
    elif sre_constants.AT_BOUNDARY == node_value: # \b
      raise NotImplementedError(f'ERROR: regex position {node_value} not implemented')
    elif sre_constants.AT_NON_BOUNDARY == node_value: # \B
      raise NotImplementedError(f'ERROR: regex position {node_value} not implemented')
    elif node_value in {sre_constants.AT_END, sre_constants.AT_END_STRING}: # a$, \Z
      raise NotImplementedError(f'ERROR: regex position {node_value} not implemented')
    else:
      raise NotImplementedError(f'ERROR: regex position {node_value} not implemented')
  else:
    raise NotImplementedError(f'ERROR: regex construct {regex_construct} not implemented')

# Translates a parsed regex into its Z3 equivalent.
# The parsed regex is a sequence of regex constructs (literals, *, +, etc.)
def regex_to_z3_expr(regex : sre_parse.SubPattern) -> z3.ReRef:
  if 0 == len(regex.data):
    raise ValueError('ERROR: regex is empty')
  elif 1 == len(regex.data):
    return regex_construct_to_z3_expr(regex[0])
  else:
    return z3.Concat([regex_construct_to_z3_expr(construct) for construct in regex.data])

# Constructs an expression evaluating whether a specific label constraint
# is satisfied by a given node, database, or k8s cluster.
# Example value for key : value parameters:
#
# 'location' : 'us-east-[\d]+'
# 'owner' : {{external.email}}
#
def matches_value(
    labels  : z3.FuncDeclRef,
    key     : z3.SeqRef,
    value   : str
  ) -> z3.BoolRef:
  constraint = parse_constraint(value)
  # 'key' : '*'
  if isinstance(constraint, AnyValueConstraint):
    return z3.BoolVal(True)
  # 'key' : 'value'
  elif isinstance(constraint, StringConstraint):
    return labels(key) == z3.StringVal(constraint.value)
  # 'key' : '(ab)*a
  elif isinstance(constraint, RegexConstraint):
    logging.debug(f'Uncompiled regex {constraint.regex}')
    regex = regex_to_z3_expr(constraint.regex)
    logging.debug(f'Compiled regex {regex}')
    return z3.InRe(labels(key), regex)
  # 'key' : '{internal.trait_key}'
  elif isinstance(constraint, UserTraitConstraint):
    logging.debug(f'User trait constraint of type {constraint.trait_type} on key {constraint.trait_key}[{constraint.inner_trait_key}]')
    if None != constraint.inner_trait_key:
      raise NotImplementedError(f'Nested trait maps are not supported: {value}')
    user_trait_type = template_types[constraint.trait_type]
    user_trait_key = z3.StringVal(constraint.trait_key)
    return user_trait_type(user_trait_key, labels(key))
  # 'key' : 'prefix#{internal.trait_key}#suffix'
  elif isinstance(constraint, InterpolationConstraint):
    logging.debug(f'User interpolation constraint of type {constraint.trait_type} on key {constraint.trait_key}[{constraint.inner_trait_key}] with prefix {constraint.prefix} and suffix {constraint.suffix}')
    if None != constraint.inner_trait_key:
      raise NotImplementedError(f'Nested trait maps are not supported: {value}')
    print(constraint)
    prefix = z3.StringVal(constraint.prefix)
    suffix = z3.StringVal(constraint.suffix)
    user_trait_type = template_types[constraint.trait_type]
    user_trait_key = z3.StringVal(constraint.trait_key)
    user_trait_value = z3.String(f'{constraint.trait_type}_{constraint.trait_key}')
    is_user_trait_value = user_trait_type(user_trait_key, user_trait_value)
    label_equals_interpolation = labels(key) == z3.Concat(prefix, user_trait_value, suffix)
    return z3.Exists(user_trait_value, z3.And(is_user_trait_value, label_equals_interpolation))
  # 'key' : '{{email.local(external.email)}}'
  elif isinstance(constraint, EmailFunctionConstraint):
    logging.debug(f'Email function constraint of type {constraint.trait_type} on key {constraint.trait_key}[{constraint.inner_trait_key}]')
    if None != constraint.inner_trait_key:
      raise NotImplementedError(f'Nested trait maps are not supported: {value}')
    user_trait_type = template_types[constraint.trait_type]
    user_trait_key = z3.StringVal(constraint.trait_key)
    user_trait_value = z3.String(f'{constraint.trait_type}_{constraint.trait_key}_email')
    is_user_trait_value = user_trait_type(user_trait_key, user_trait_value)
    label_equals_email_local = labels(key) == z3.SubString(user_trait_value, z3.IntVal(0), z3.IndexOf(user_trait_value, z3.StringVal('@')) + z3.IntVal(1))
    return z3.Exists(user_trait_value, z3.And(is_user_trait_value, label_equals_email_local))
  # 'key' : '{{regexp.replace(external.access["env"], "^(staging)$", "$1")}}'
  elif isinstance(constraint, RegexReplaceFunctionConstraint):
    logging.debug(f'Regexp replace function constraint of type {constraint.trait_type} on key {constraint.trait_key}[{constraint.inner_trait_key}], replacing {constraint.pattern} with {constraint.replace}')
    raise NotImplementedError(f'Regexp replace function constraint not yet supported given {key} : {value}')
  else:
    raise NotImplementedError(f'Unknown constraint value type {value}; not supported.')

# Constructs an expression evaluating whether a specific label constraint
# is satisfied by a given node, database, or k8s cluster; constraint can
# take the form of a list of permissible values.
# Example value for key : value parameters:
#
# 'env' : ['test', 'prod']
#
def matches_constraint(
    labels      : z3.FuncDeclRef,
    label_keys  : z3.FuncDeclRef,
    key         : str,
    value       : typing.Union[str, list[str]]
  ) -> z3.BoolRef:
  logging.debug(f'Compiling {key} : {value} constraint')
  if '*' == key:
    if '*' == value:
      return z3.BoolVal(True)
    else:
      raise ValueError(f'Constraint of type \'*\' : {value} is not valid')

  key = z3.StringVal(key)
  if isinstance(value, list):
    return z3.And(label_keys(key), z3.Or([matches_value(labels, key, v) for v in value]))
  else:
    return z3.And(label_keys(key), matches_value(labels, key, value))
  

# Constructs an expression evaluating to whether a given set of label
# requirements are satisfied by a given node, database, or k8s cluster.
# Example value for constraints parameter:
#
# {'env' : ['test', 'prod'], 'location' : 'us-east-[\d]+' }
#
def matches_constraints(
    constraint_type : str,
    labels          : z3.FuncDeclRef,
    label_keys      : z3.FuncDeclRef,
    constraints     : dict[str, typing.Union[str, list[str]]]
  ) -> z3.BoolRef:
  logging.debug(f'Compiling {constraint_type} constraints')
  return z3.And([
    matches_constraint(labels, label_keys, key, value)
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
def matches_constraint_group(
    group : dict[str, dict[str, typing.Union[str, list[str]]]]
  ) -> z3.BoolRef:
  return z3.Or([
    constraint_type in group
    and matches_constraints(constraint_type, labels, label_keys, group[constraint_type])
    for constraint_type, (labels, label_keys) in entity_types.items()
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
def allows(role : typing.Any) -> z3.BoolRef:
  role_name = role['metadata']['name']
  logging.debug(f'Compiling role template {role_name}')
  spec = role['spec']
  logging.debug('Compiling allow constraints')
  allow_expr = 'allow' in spec and matches_constraint_group(spec['allow'])
  logging.debug('Compiling deny constraints')
  deny_expr = 'deny' in spec and matches_constraint_group(spec['deny'])
  return z3.And(allow_expr, z3.Not(deny_expr))

# Determines whether the given role is a role template, filled in by user traits.
def is_role_template(role) -> bool:
  spec = role['spec']
  if 'allow' in spec:
    allow = spec['allow']
    groups = [allow[constraint_type].values() for constraint_type in entity_types.keys() if constraint_type in allow]
    if any([requires_user_traits(value) for values in groups for value in values]):
      return True

  if 'deny' in spec:
    deny = spec['deny']
    groups = [deny[constraint_type] for constraint_type in entity_types.keys() if constraint_type in deny]
    if any([requires_user_traits(value) for values in groups for value in values]):
      return True

  return False

# Compiles the labels of a given node, k8s cluster, or database into a
# form understood by Z3 that can be checked against a compiled set of role
# constraints.
def labels_as_z3_map(
    concrete_labels : typing.Optional[dict[str, str]],
    constraint_type : EntityType
  ) -> z3.BoolRef:
  logging.debug(f'Compiling labels {concrete_labels} of type {constraint_type.name}')
  labels, label_keys = constraint_type.value
  if concrete_labels is not None and any(concrete_labels):
    included = z3.And([label_keys(z3.StringVal(key)) for key in concrete_labels.keys()])
    excluded_key = z3.String('excluded_key')
    is_excluded_key = z3.And([excluded_key != z3.StringVal(key) for key in concrete_labels.keys()])
    excluded = z3.Implies(is_excluded_key, z3.Not(label_keys(excluded_key)))
    restrictive_key_set = z3.And(included, z3.ForAll(excluded_key, excluded))
    return z3.And(restrictive_key_set, z3.And([
      labels(z3.StringVal(key)) == z3.StringVal(value)
      for key, value in concrete_labels.items()
    ]))
  else:
    any_key = z3.String('any_key')
    return z3.ForAll(any_key, z3.Not(label_keys(any_key)))

# Compiles the traits of a given internal or external user into a form
# understood by Z3 that can be checked against a compiled set of role constraints.
def traits_as_z3_map(
    concrete_traits : typing.Optional[dict[str, list[str]]],
    user_type : UserType
  ) -> typing.Optional[z3.BoolRef]:
  logging.debug(f'Compiling user traits {concrete_traits} of type {user_type.name}')
  traits = user_type.value
  if concrete_traits is not None and any(concrete_traits):
    included = z3.And([
      traits(z3.StringVal(key), (z3.StringVal(value)))
      for key, values in concrete_traits.items() for value in values
    ])
    return included
    #excluded_key = z3.String('excluded_key')
    #any_value = z3.String('any_value')
    #is_excluded_key = z3.And([excluded_key != z3.StringVal(key) for key in concrete_traits.keys()])
    #excluded_keys_excluded = z3.Implies(is_excluded_key, z3.Not(traits(excluded_key, any_value)))
    #exclude_excluded_keys = z3.ForAll([excluded_key, any_value], excluded_keys_excluded)
    #included_key = z3.String('included_key')
    #excluded_value = z3.String('excluded_value')
    #is_included_key = z3.Or([included_key == z3.StringVal(key) for key in concrete_traits.keys()])
    #is_excluded_value = z3.And([
    #  z3.Implies(included_key == z3.StringVal(key), excluded_value != z3.StringVal(value))
    #  for key, values in concrete_traits.items() for value in values
    #])
    #excluded_values_excluded = z3.Implies(z3.And(is_included_key, is_excluded_value), z3.Not(traits(included_key, excluded_value)) )
    #exclude_excluded_values = z3.ForAll([included_key, excluded_value], excluded_values_excluded)
    #return z3.And(included, exclude_excluded_keys, exclude_excluded_values)
  else: # User does not have any traits.
    any_key = z3.String('any_key')
    any_value = z3.String('any_value')
    return z3.ForAll([any_key, any_value], z3.Not(user_type.value(any_key, any_value)))

# Determines whether the given role provides the user access to the entity.
# Does not check whether the user actually possesses that role.
def role_allows_user_access_to_entity(
    role          : typing.Any,
    user_traits   : typing.Optional[dict[str, str]],
    user_type     : UserType,
    entity_labels : dict[str, str],
    entity_type   : EntityType,
    solver        : z3.Solver = z3.Solver()
  ) -> bool:
  solver.add(traits_as_z3_map(user_traits, user_type))
  solver.add(labels_as_z3_map(entity_labels, entity_type))
  if z3.sat == solver.check():
    print(solver.model())
    result = solver.model().evaluate(allows(role), model_completion=True)
    if isinstance(result, z3.QuantifierRef):
      solver.push()
      solver.add(result)
      quantification_result = solver.check()
      solver.pop()
      return z3.sat == quantification_result
    else:
      return result
  else:
    raise ValueError(f'User traits {user_traits} of type {user_type.name} and entity labels {entity_labels} of type {entity_type.name} do not produce a valid model.')