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
        print(f'Role {role_name} is a role template; try specifying --users to check who has access')
      else:
        result = s.model().evaluate(allows(role), model_completion=True)
        if result:
          print(f'Node {node_name} matches role {role_name}')
        else:
          print(f'Node {node_name} does not match role {role_name}')
    s.pop()

def node_matches_user(nodes, roles, users):
  return True

def main():
  parser = argparse.ArgumentParser(description='Determine which nodes match which roles. If path to users file is given, can resolve role templates and determine which users have access to which nodes.')
  parser.add_argument('nodes', metavar='NODES', type=argparse.FileType('r'), help='Path to the nodes yaml file')
  parser.add_argument('roles', metavar='ROLES', type=argparse.FileType('r'), help='Path to the roles yaml file')
  parser.add_argument('-u', '--users', dest='users', metavar='USERS', default='', type=str, help='Path to the users yaml file')
  parser.add_argument('-d', '--debug', dest='log_level', action='store_const', const=logging.DEBUG, default=logging.INFO, help='Print Z3 translation debug output')
  args = parser.parse_args()

  logging.basicConfig(level=args.log_level)

  try:
    nodes = [yaml.safe_load(node) for node in args.nodes.read().split('---')]
    roles = [yaml.safe_load(role) for role in args.roles.read().split('---')]
    if '' == args.users:
      node_matches_role(nodes, roles)
    else:
      with open(args.users, 'r') as users:
        users = [yaml.safe_load(user) for user in users.read().split('---')]
        node_matches_user(nodes, roles, users)
  except yaml.YAMLError as e:
    print(e)

  args.nodes.close()
  args.roles.close()

if __name__ == '__main__':
  main()
