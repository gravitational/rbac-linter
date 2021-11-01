import yaml
from z3 import *

# Datatypes
node_labels = Array('node_labels', StringSort(), StringSort())

kv = Datatype('kv')
kv.declare('kv', ('key', StringSort()), ('value', StringSort()))
kv = kv.create()
#kv1 = kv.kv(StringVal('foo'), StringVal('bar'))

def analyze(role_template):
  allow_expr = BoolVal(True)
  spec = role_template['spec']
  if 'allow' in spec:
    allow = spec['allow']
    if 'node_labels' in allow:
      constraints = allow['node_labels']
      for key, value in constraints.items():
        key = StringVal(key)
        if isinstance(value, list):
          list_expr = BoolVal(False)
          for v in value:
            list_expr = Or(list_expr, Select(node_labels, key) == StringVal(v))
          allow_expr = And(allow_expr, list_expr)
        else:
          allow_expr = And(allow_expr, Select(node_labels, key) == StringVal(value))

  deny_expr = BoolVal(True)
  if 'deny' in spec:
    deny = spec['deny']
    if 'node_labels' in deny:
      constraints = deny['node_labels']
      for key, value in constraints.items():
        key = StringVal(key)
        if isinstance(value, list):
          list_expr = BoolVal(False)
          for v in value:
            list_expr = Or(list_expr, Select(node_labels, key) == StringVal(v))
          deny_expr = And(deny_expr, list_expr)
        else:
          deny_expr = And(deny_expr, Select(node_labels, key) == StringVal(value))

  s = Solver()
  s.add(And(allow_expr, Not(deny_expr)))
      
  #x = String('x')
  #ab = Star(Re('ab'))
  #s.add(InRe(x, ab), Length(x) == 6)

  print(s.check())
  print(s.model())

with open('../data/role.yml', 'r') as role_template_file:
  try:
    role_template = yaml.safe_load(role_template_file)
    analyze(role_template)
  except yaml.YAMLError as e:
    print(e)
