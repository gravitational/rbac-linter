import argparse
import logging
from role_analyzer import allows, is_role_template, labels_as_z3_map, ConstraintType
import yaml
from z3 import *

def node_matches_role(nodes, roles):
  s = Solver()
  for node in nodes:
    s.push()
    node_name = node['spec']['hostname']
    node_labels = node['metadata']['labels']
    s.add(labels_as_z3_map(node_labels, ConstraintType.NODE))
    s.check()
    for role in roles:
      role_name = role['metadata']['name']
      if is_role_template(role):
        print(f'Role {role_name} is a role template so it is unknown whether it is matched by node {node_name}')
      else:
        result = s.model().evaluate(allows(role), model_completion=True)
        if result:
          print(f'Node {node_name} matches role {role_name}')
        else:
          print(f'Node {node_name} does not match role {role_name}')
    s.pop()

parser = argparse.ArgumentParser(description='Determine which nodes match which roles.')
parser.add_argument('nodes', metavar='NODES', type=str, help='Path to the nodes yaml file')
parser.add_argument('roles', metavar='ROLES', type=str, help='Path to the roles yaml file')
parser.add_argument('--debug', dest='log_level', action='store_const', const=logging.DEBUG, default=logging.INFO, help='Print Z3 translation debug output')
args = parser.parse_args()

logging.basicConfig(level=args.log_level)

with (
  open(args.nodes, 'r') as nodes,
  open(args.roles, 'r') as roles
):
  try:
    nodes = [yaml.safe_load(node) for node in nodes.read().split('---')]
    roles = [yaml.safe_load(role) for role in roles.read().split('---')]
    node_matches_role(nodes, roles)
  except yaml.YAMLError as e:
    print(e)
