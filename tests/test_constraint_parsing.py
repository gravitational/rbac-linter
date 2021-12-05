from role_analyzer import requires_user_traits, parse_constraint, ValueType
import sre_parse

def parse_match_any_constraint():
  unparsed = '*'
  expected = unparsed
  assert not requires_user_traits(unparsed), unparsed
  constraint_type, actual = parse_constraint(unparsed)
  assert ValueType.MATCH_ANY == constraint_type, unparsed
  assert expected == actual, unparsed

def test_parse_template_constraint():
  values = [
    ('internal', 'key', None),
    ('external', 'key', None),
    ('internal', 'key', 'inner'),
    ('external', 'key', 'inner')
  ]
  
  for expected in values:
    trait_type, trait_key, inner_key = expected
    unparsed = f'{{{{{trait_type}.{trait_key}}}}}' if None == inner_key \
      else f'{{{{{trait_type}.{trait_key}["{inner_key}"]}}}}'
    assert requires_user_traits(unparsed), unparsed
    constraint_type, actual = parse_constraint(unparsed)
    assert ValueType.TEMPLATE == constraint_type, unparsed
    assert expected == actual, unparsed

def test_parse_interpolation_constraint():
  values = [
    ('prefix', 'internal', 'key', None, 'suffix'),
    ('prefix', 'external', 'key', None, 'suffix'),
    ('prefix', 'internal', 'key', 'inner', 'suffix'),
    ('prefix', 'external', 'key', 'inner', 'suffix')
  ]
  
  for expected in values:
    prefix, trait_type, trait_key, inner_key, suffix = expected
    unparsed = f'{prefix}{{{{{trait_type}.{trait_key}}}}}{suffix}' if None == inner_key \
      else f'{prefix}{{{{{trait_type}.{trait_key}["{inner_key}"]}}}}{suffix}'
    assert requires_user_traits(unparsed), unparsed
    constraint_type, actual = parse_constraint(unparsed)
    assert ValueType.INTERPOLATION == constraint_type, unparsed
    assert expected == actual, unparsed

def test_parse_email_function_constraint():
  values = [
    ('internal', 'key', None),
    ('external', 'key', None),
    ('internal', 'key', 'inner'),
    ('external', 'key', 'inner')
  ]
  
  for expected in values:
    trait_type, trait_key, inner_key = expected
    unparsed = f'{{{{email.local({trait_type}.{trait_key})}}}}' if None == inner_key \
      else f'{{{{email.local({trait_type}.{trait_key}["{inner_key}"])}}}}'
    assert requires_user_traits(unparsed), unparsed
    constraint_type, actual = parse_constraint(unparsed)
    assert ValueType.EMAIL_FUNCTION == constraint_type, unparsed
    assert expected == actual, unparsed

def test_parse_regexp_replace_function_constraint():
  values = [
    ('internal', 'key', None, 'pattern', 'replacement'),
    ('external', 'key', None, 'pattern', 'replacement'),
    ('internal', 'key', 'inner', 'pattern', 'replacement'),
    ('external', 'key', 'inner', 'pattern', 'replacement')
  ]
  
  for expected in values:
    trait_type, trait_key, inner_key, pattern, replacement = expected
    unparsed = f'{{{{regexp.replace({trait_type}.{trait_key}, "{pattern}", "{replacement}")}}}}' if None == inner_key \
      else f'{{{{regexp.replace({trait_type}.{trait_key}["{inner_key}"], "{pattern}", "{replacement}")}}}}'
    assert requires_user_traits(unparsed), unparsed
    constraint_type, actual = parse_constraint(unparsed)
    assert ValueType.REGEXP_REPLACE_FUNCTION == constraint_type, unparsed
    assert expected == actual, unparsed

def test_parse_regex_constraint():
  values = [
    r'a{3}',
    r'aa*', r'a*a',
    r'(ab)*a', r'a(ba)*',
    r'[\d]*', r'[0-9]*',
    r'[\D]*', r'[^\d]*',
    r'[\s]*', r'[ \t\n\r\f\v]*',
    r'[\S]+', r'[^ \t\n\r\f\v]+',
    r'[\w]?', r'[a-zA-Z0-9_]?',
    r'[\W]{3,5}', r'[^a-zA-Z0-9_]{3,5}',
    r'.{0,2}', r'.?.?',
    r'[abc]d', r'(ad|bd|cd)',
    r'[a-c]{10-11}', r'[abc]{10-11}'
  ]
  
  for unparsed in values:
    assert not requires_user_traits(unparsed), unparsed
    constraint_type, _ = parse_constraint(unparsed)
    assert ValueType.REGEX == constraint_type, unparsed

def test_parse_string_constraint():
  values = ['foo', 'bar', 'baz', 'foobar']
  
  for unparsed in values:
    expected = unparsed
    assert not requires_user_traits(unparsed), unparsed
    constraint_type, actual = parse_constraint(unparsed)
    assert ValueType.STRING == constraint_type, unparsed
    assert expected == actual, unparsed

