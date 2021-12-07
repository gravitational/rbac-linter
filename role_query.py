import argparse
import logging
from role_analyzer import allows, is_role_template, labels_as_z3_map, traits_as_z3_map, EntityType, UserType
import yaml
from z3 import Solver # type: ignore

def node_matches_role(nodes, roles):
  s = Solver()
  for node in nodes:
    s.push()
    node_name = node['spec']['hostname']
    node_labels = node['metadata']['labels']
    s.add(labels_as_z3_map(node_labels, EntityType.NODE))
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
  s = Solver()
  for node in nodes:
    s.push()
    node_name = node['spec']['hostname']
    node_labels = node['metadata']['labels']
    s.add(labels_as_z3_map(node_labels, EntityType.NODE))
    
    for user in users:
      s.push()
      user_name = user['metadata']['name']
      user_traits = user['spec']['traits']
      s.add(traits_as_z3_map(user_traits, UserType.INTERNAL))
      s.check()

      user_role_names = user['spec']['roles']
      user_roles = filter(lambda role : role['metadata']['name'] in user_role_names, roles)
      for role in user_roles:
        role_name = role['metadata']['name']
        result = s.model().evaluate(allows(role), model_completion=True)
        if result:
          print(f'User {user_name} has access to {node_name} via role {role_name}')
        else:
          print(f'User {user_name} does NOT have access to {node_name} via role {role_name}')
      s.pop()
    s.pop()

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
