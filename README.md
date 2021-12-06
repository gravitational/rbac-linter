# rbac-linter
[![Build & Test](https://github.com/gravitational/rbac-linter/actions/workflows/ci.yml/badge.svg)](https://github.com/gravitational/rbac-linter/actions/workflows/ci.yml)

This is an analysis engine for role-based access control (RBAC) in [Teleport](https://goteleport.com/docs/access-controls/guides/role-templates/) using the [Z3 theorem prover](https://github.com/Z3Prover/z3) from Python.
It enables comparison of role templates for logical equivalence across all possible users and nodes, or to check that one role template is a subset of another or that it implements a specific security policy.
It also enables linting sets of roles to detect duplicates.

## Build & Test

1. Install dependencies:
   * [Python 3.x](https://www.python.org/downloads/)
2. Restore Python packages:
   * `pip install -r requirements.txt --user`
3. Run unit tests:
   * `python test.py`

## Use: role equivalence checking

This program checks whether two roles are logically equivalent - both admit the same sets of users to the same sets of nodes.
Z3 enables this without requiring a list of users or nodes; both are represented as abstract entities whose traits can take on any possible value.

The program takes two role templates as input, in YAML form.
You can get a YAML role description from a Teleport cluster with the command `tctl get roles/role-name`.
Write these YAML descriptions to two separate files, then run the program as follows:

```
python role_equivalence_check.py path/to/first-role.yml path/to/second-role.yml
```

You can add the `--debug` flag to see output from the program as it compiles the roles into expressions understood by Z3.

Two example roles are provided in this repo for ease of demonstration; compare them as follows:

```
python role_equivalence_check.py data/role.yml data/role2.yml
```

If the roles are not equivalent, the script will provide an example of a node, user, or user/node pair which is accepted by one role but blocked by the other; these examples can be somewhat difficult to decipher as they are produced by a SMT solver, but can be interpreted with some practice.

## Use: role querying

Given a set of users, roles, and nodes, this program will print out which users have access to which nodes via which roles.
It is mostly useful as a demonstration of how to write an application using the functions provided by the underlying analysis engine; the role analysis logic is the identical to that used by the above equivalence checker.
It can also be used to test the analysis engine against the actual workings of the Teleport RBAC system itself, as the analysis engine attempts to exactly match its functionality.

You can get YAML descriptions of all users, roles, and nodes from a Teleport cluster with the `tctl get users`, `tctl get roles`, and `tctl get nodes` commands respectively.
Example data is provided in this repo for ease of demonstration; run this program as follows:
```
python role_query.py data/nodes.yml data/roles.yml --users data/users.yml
```

This application currently only fully supports setups with internal Teleport users, since there is no practical way to dump the OIDC claims of all users in an external auth provider.
If the roles do not access user traits then user details are not necessary for the program to function.
You can omit the `--users` command line parameter and the program will simply skip any roles that access user traits.

## Supported constraints and limitations

The analysis engine supports the following types of constraints:
 * Matching any trait value:
   * `'key' : '*'`
   * `'*' : '*'`
 * Simple literal string comparisons over Unicode characters:
   * `'key' : 'value'`
   * `'鑰匙' : '∀∃'`
 * Regular expressions over ASCII characters:
   * `'key' : '(ab)*a'`
 * Templated values from user traits (which may themselves be lists):
   * `'key' : '{{internal.trait}}'`
 * Strings interpolated from user traits (which themselves may be lists):
   * `'key' : 'foo#{{external.logins}}#bar'`
 * The `email.local` function:
   * `'key' : '{{email.local(external.email)}}'`
 * Mixed lists of all of the above:
   * `'key' : ['value', '(ab)*a', '{{internal.trait}}']`

The analysis engine does **not** currently support the following types of constraints:
 * Regular expressions over Unicode characters:
   * `'key' : '(∀∃)*∀'`
 * `^` (start) and `$` (end) tokens in regexes:
   * `'key' : '^(ab)*a$'`
 * Nested maps in user traits:
   * `'key' : '{{external.trait["inner_key"]}}'`
 * The `regexp.replace` function:
   * `'key' : '{{regexp.replace(external.env, "^(staging)$", "$1")}}'`

It is possible that the first three could become supported by the analysis system with some work and trickery.
The `regexp.replace` is much more complicated and seem likely to require work to extend the capabilities of Z3 itself.

## Z3 issues impacting this project
#### [Regex performance cliff when using InRe](https://github.com/Z3Prover/z3/issues/5648)
This means overly-complicated regular expressions are likely to cause the analysis engine to run forever; however, the fix is not complicated and will hopefully be included in a near-future release; direct comparison of the same regular expressions is usually quite fast.
#### [Possible regression in model output for functions from strings to strings in python](https://github.com/Z3Prover/z3/issues/5674)
This impacts how the counterexample models are displayed in the role equivalence check program, if the roles are not equivalent.
This has been fixed but the fix is not present in the latest Z3 4.8.13 release; as a workaround you can download the `.whl` file from the [Z3 nightly build](https://github.com/Z3Prover/z3/releases/tag/Nightly) and install it with the command `python -m pip install z3_solver-*.whl --user`
#### [Regex performance regression from 4.8.12 to 4.8.13](https://github.com/Z3Prover/z3/issues/5693)
This makes previously-solvable regexes take forever.
However, the regexes involved are quite complicated so would likely be unsolvable due to the above issue anyway.
