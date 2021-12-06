import os
import pytest
from role_equivalence_check import roles_are_equivalent
from role_analyzer import is_role_template
import yaml

@pytest.fixture
def change_test_dir(request):
    os.chdir(request.fspath.dirname)
    yield
    os.chdir(request.config.invocation_dir)

def test_roles_are_equivalent(change_test_dir):
  with open('data/role_equivalence_tests.yml', 'r') as tests:
    tests = [yaml.safe_load(test) for test in tests.read().split('---')]
    for test in tests:
      test_name = test['test-name']
      r1 = test['first-role']
      r2 = test['second-role']
      expected_are_equivalent = test['are-equivalent']
      is_template = test['is-template']
      assert is_template == is_role_template(r1), test_name
      assert is_template == is_role_template(r2), test_name
      actual_are_equivalent, msg = roles_are_equivalent(r1, r2)
      assert expected_are_equivalent == actual_are_equivalent, (test_name, msg)
