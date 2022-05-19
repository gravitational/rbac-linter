# rbac-linter
[![Build & Test](https://github.com/gravitational/rbac-linter/actions/workflows/ci.yml/badge.svg)](https://github.com/gravitational/rbac-linter/actions/workflows/ci.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

This is an analysis engine for role-based access control (RBAC) in [Teleport](https://goteleport.com/docs/access-controls/guides/role-templates/) using the [Z3 theorem prover](https://github.com/Z3Prover/z3) from Python.
It enables comparison of role templates for logical equivalence across all possible users and nodes, or to check that one role template is a subset of another or that it implements a specific security policy.
It also enables linting sets of roles to detect duplicates.

## Build & Test

1. Install dependencies:
   * [Python 3.9](https://www.python.org/downloads/)
2. Restore Python packages:
   * `pip install -r requirements.txt --user`
3. Run unit tests:
   * `python3.9 -m pytest`

*Note* On ubuntu, follow these steps to install pip for python 3.9: https://stackoverflow.com/questions/65644782/how-to-install-pip-for-python-3-9-on-ubuntu-20-04
Then install pytest: `python3.9 -m pip install pytest`

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
1. Nested maps in user traits:
   * `'key' : '{{external.trait["inner_key"]}}'`
2. Regular expressions over Unicode characters:
   * `'key' : '(∀∃)*∀'`
3. `^` (start) and `$` (end) tokens in regexes:
   * `'key' : '^(ab)*a$'`
4. Regexes that use min-matching semantics:
   * `'key' : '(ab){3,5}?'`
   * `'key' : 'x??'`
5. The `regexp.replace` function:
   * `'key' : '{{regexp.replace(external.env, "^(staging)$", "$1")}}'`

It is possible that the first three could become supported by the analysis system with some work and trickery.
Regex min-matching and `regexp.replace` are much more complicated and require work to extend the capabilities of Z3 itself.
Beyond extending the [Z3 Replace](https://z3prover.github.io/api/html/namespacez3py.html#a667df8f95f4ad180a229c65f80c63f87) API to work with regexes instead of just strings, regex capturing groups would also have to be implemented.

## Technical overview

This project sets up a set of constraints over three sorts of constants: users, roles, and entities.
Users possess certain roles, which grant or deny them access to particular entities.
Users can be either external or internal, and possess a dictionary of traits where each string key maps to a set of string values.
Entities can be apps, nodes, kubernetes clusters, or databases, and possess a dictionary of labels where each string key maps to a single string value.
Roles function as a boolean expression over user traits and entity labels, determining whether a user is granted access to an entity.
Teleport possesses a large variety of possible role constraints, documented [here](https://goteleport.com/docs/access-controls/reference/#roles).

This work is conceptually similar to prior work [checking equivalence of firewalls](https://ahelwer.ca/post/2018-02-13-z3-firewall/), but here the constraints are over strings instead of IP addresses and ports.
You can read more about this project on [the Teleport blog](https://goteleport.com/blog/z3-rbac/).

## Z3 issues impacting this project
#### [Regex performance cliff when using InRe](https://github.com/Z3Prover/z3/issues/5648)
This means overly-complicated regular expressions are likely to cause the analysis engine to run forever; however, the fix is not complicated and will hopefully be included in a near-future release; direct comparison of the same regular expressions is usually quite fast.
#### [Regex performance regression from 4.8.12 to 4.8.13](https://github.com/Z3Prover/z3/issues/5693)
This makes previously-solvable regexes take forever.
However, the regexes involved are quite complicated so would likely be unsolvable due to the above issue anyway.
