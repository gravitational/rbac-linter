import os
import pytest
from role_analyzer import role_allows_user_access_to_entity, UserType, EntityType
import yaml
from z3 import Solver # type: ignore

@pytest.fixture
def change_test_dir(request):
    os.chdir(request.fspath.dirname)
    yield
    os.chdir(request.config.invocation_dir)

def test_role_querying(change_test_dir):
  with open('data/role_querying_tests.yml', 'r') as tests:
    tests = yaml.safe_load(tests)
    solver = Solver()
    for test in tests['tests']:
      solver.push()
      test_name = test['name']
      user_type = UserType[test['user']['type']]
      user_traits = test['user']['traits']
      entity_type = EntityType[test['entity']['type']]
      entity_labels = test['entity']['labels']
      role = test['role']
      expected = test['allows']
      actual = role_allows_user_access_to_entity(role, user_traits, user_type, entity_labels, entity_type, solver)
      success = expected == actual
      if not success:
        print(user_traits)
        print(entity_labels)
        if actual:
          print(solver.model())
      assert expected == actual, test_name
      solver.pop()
