---
title: Regexes in the Z3 Theorem Prover
subtitle: Analyzing Teleport RBAC
date: 2021-12-21
bigimg: [{src: "/img/z3-rbac/el-yunque.jpg", desc: "El Yunque rainforest in Puerto Rico"}]
tags: ["Formal Methods"]
draft: true
---

Z3 is a satisfiability modulo theories (SMT) solver developed by Microsoft Research.
With a description like that, you'd expect it to be restricted to esoteric corners of the computerized mathematics world, but it has made impressive inroads addressing conventional software engineering needs: analyzing [network ACLs](https://www.microsoft.com/en-us/research/blog/hyperscale-cloud-reliability-and-the-art-of-organic-collaboration/) and [firewalls](https://github.com/Z3Prover/FirewallChecker) in Microsoft Azure, for example.
Z3 is used to answer otherwise-unanswerable questions like "are these two firewalls equivalent?" or "does this set of network ACLs violate any security rules?".

While those applications dealt with constraints over IP addresses (essentially very large numbers), Z3 can also analyze constraints over strings; this was used to implement [AWS Zelkova](https://www.cs.utexas.edu/users/hunt/FMCAD/FMCAD18/papers/paper3.pdf) which analyzes role-based access control (RBAC) policies in the Amazon cloud.
Of course, modern RBAC systems go beyond simple string comparison: they also include regular expressions!
Z3 can actually handle these too, although at the time of development (pre-2018) AWS Zelkova ran into issues with Z3's regex module so extended it with their own solver called Z3 Automata.
Z3 Automata was sadly never open-sourced, but the following years saw a ton of work put into Z3's string and regex functionality.
So when [Teleport](https://goteleport.com/) approached me to prototype an analysis engine for their own (quite advanced!) RBAC system, it provided an ideal opportunity to take this new hotness for a spin!

What questions can we ask about a RBAC system?
The most basic is this: are two roles the same?
Do they admit the same set of users to the same set of nodes?
Here's how I used Z3 to answer that question, analyzing constraints involving string equality, regexes, interpolation, and even some basic string functions — by the end you'll know how to do it too!
You can even use the tool developed during the contract, because it's [open source](https://github.com/gravitational/rbac-linter/).

## What are we doing when we use Z3?

Before diving in, it's worth explaining the Z3 paradigm at a high level.
Z3 is an [open-source](https://github.com/Z3Prover/z3) MIT-licensed C++ library predominantly developed by Microsoft Research.
It has bindings for a number of popular languages; I'll use Python 3 here, so if you'd like to follow along it's as easy as going `pip install z3-solver` then `import z3` at the top of a new Python file.

When we write a program that uses Z3, fundamentally what we're doing is building the *syntax tree* of some logical or mathematical formula which Z3 will then solve for us.
For this reason it's nice to use a high-level scripting language like Python, because all the performance-critical magic is done inside a final call to the Z3 `check()` function; the scripting code building the syntax tree is essentially irrelevant to the overall performance of the program.

So what does this look like?
Let's go back to early gradeschool algebra!
Say we want to solve a simple equation, like `x = y + 2`.
What this means is we want to know whether there (1) exists any values of `x` and `y` satisfying this equation at all, and (2) example values of `x` and `y` if a solution indeed exists.
We call these example values a *model*, which is a term you might recall if you've taken an undergraduate course in formal logic.
Anyway, here's how you'd write this in Python:
```python
import z3

solver = z3.Solver()
x = z3.Int('x')
y = z3.Int('y')
solver.add(x == y + 2)
result = solver.check()
if z3.sat == result:
    print(solver.model())
else:
    print('No solution!')

```
This should print out a model, for example:
```
[y = 0, x = 2]
```
The above program constructs a very simple syntax tree: we define two variables `x` and `y` of sort `z3.Int`, then pass the expression `x == y + 2` to the solver.
Z3 overloads the `==` and `+` operators in Python so this creates the formula you'd expect.
The call to `solver.check()` then checks whether the given formula is satisfiable (it is), and we print out the model if it exists (it does).

You can see how Z3 handles an unsatisfiable set of constraints by adding another line containing a contradictory equation before the call to `solver.check()`:
```python
solver.add(x == y - 2)
```
This all seems a bit magical — what is Z3 doing in the `check()` function?
How does it find model values?
How weird can the constraints get?
The answer is quite weird — impressively weird!
Modern SMT solvers are consistently surprising in their power.
Not all is rainbows, of course — you'll sometimes run into performance "cliffs" where a minor change to a formula spells the difference between sub-second verification and running until the heat death of the universe.
But these often have workarounds; I promise you can get much further than you'd think!

## Role-based access control in Teleport

If you work at a company that follows modern authentication & authorization practices, you probably use RBAC.
The basic idea is that organizations all have a set of users (employees) and a set of resources (servers, databases, etc.), and various subsets of users need to have access to various subsets of resources.
Controlling this access is a difficult problem that only becomes more difficult as the users and resources grow in number.
One common solution is to add a third mediating entity called a role, where users possess certain roles (database admin, developer, business analyst, etc.) and those roles have access to certain permissions on certain resources (admin access to a production server, read access to a database, etc.)
You can get even fancier with just-in-time permission elevation where users temporarily attain powerful roles (after signoff from peers) to respond to incidents, but that's beyond the scope of this post.

I should here add a disclaimer — Teleport is compensating me for writing this post as an extension of our contract.
Teleport is a company that implements sophisticated RBAC for SSH, Kubernetes, web apps, and databases.
They have both an enterprise offering and an [open source core](https://github.com/gravitational/teleport) which is pretty nifty to set up on your homelab — I can now reverse-tunnel into the Raspberry Pi sitting on my shelf from anywhere in the world after authenticating with GitHub, which is fun!

Anyway, roles in Teleport RBAC are basically boolean functions on two things: traits possessed by users, and labels advertised by nodes.
The supported constraints are documented [here](https://goteleport.com/docs/access-controls/guides/role-templates/), although we'll go over a few in the next section.

## Compiling roles to Z3 expressions

Remember why we're here: we want to compare two roles for logical equivalence.
How do we do that?
First, a brief tour of our entity model is in order.

A Teleport cluster consists of a set of resources (nodes, kubernetes clusters, etc.) running the Teleport client to govern access to themselves.
Consider a user authenticating with GitHub, or Microsoft Exchange, or Okta to get access to a Teleport cluster.
They'll be given a token containing a set of OpenID Connect (OIDC) claims, perhaps:
```yaml
username : 'jdoe'
name     : 'John Doe'
country  : 'Canada'
```
Meanwhile, there might be a node advertising the following labels to the Teleport cluster:
```yaml
labels:
  location: 'Canada'
  running: 'fooapp'
```
Then, we can have a role allowing SSH access to any nodes running `fooapp` in the same country as the user:
```yaml
allow:
  node_labels:
    location: '{{external.country}}'
    running: 'fooapp'
```
Possession of this role also might be predicated on whether the user is a member of a certain team or organization on GitHub.
In this case, the role would allow the user to access the node.

If we were to represent the role as a boolean expression evaluating to true or false where true means "access granted" and false means "access denied", it would look something like this:

`(node.location = user.country) ∧ (node.running = 'fooapp')`

How might we represent this in Z3?
Here's a simple first attempt in Python:
```python
import z3

user_country = z3.String('user_country')
node_location = z3.String('node_location')
node_running = z3.String('node_running')
role1 = z3.And(user_country == node_location, node_running == z3.StringVal('fooapp'))
```

Here we see our first use of strings in Z3.
They work how you'd expect - we can compare them with `==`.
Note the difference between `z3.String` and `z3.StringVal`; the former defines a new unbound string variable with the given name, and the latter defines a constant literal string value.
So we've defined a boolean expression representing the role.
What can we do with it?
Well, certainly we can ask Z3 whether the role is satisfiable:
```python
solver = z3.Solver()
solver.add(role1)
result = solver.check()
if z3.sat == result:
  print(solver.model())
else:
  print('No solution!')
```
But that isn't very useful. 
Z3 just generates some not-very-realistic values of `user_country`, `node_location`, and `node_running` that satisfy our constraints.
Remember: we want to do this so we can compare two roles!
So let's define another role, a weird one where users can only access nodes running `fooapp` in countries where they *aren't* located:
```yaml
allow:
  node_labels:
    location: '*'
    running: 'fooapp'
deny:
  node_labels:
    location: '{{external.country}}'
```
Note `'*'` is a wildcard token matching any value, and `deny` constraints take precedence over `allow` constraints.
Write this role in Z3 as follows:
```python
role2 = z3.And(user_country != node_location, node_running == z3.StringVal('fooapp'))
```
Then ask Z3 whether the two roles are distinct:
```python
solver = z3.Solver()
solver.add(z3.Distinct(role1, role2))
result = solver.check()
if z3.sat == result:
  print(solver.model())
else:
  print('No solution!')
```
They're different!
Z3 finds us some user traits and node labels that are allowed by one role but denied by the other.
This illustrates a great benefit of SMT solvers in this domain: not only do they tell you whether access control rules are equivalent, but by finding a model they also give you a great start on debugging *why* they aren't equivalent.

One last hidden benefit of representing our roles this way is we can check whether the role allows a specific user to access a specific resource by tightly constraining the variables to specific values.
Using our above example:
```python
solver = z3.Solver()
solver.add(role1)
solver.add(user_country == 'Canada')
solver.add(node_location == 'Canada')
solver.add(node_running == 'fooapp')
result = solver.check()
if z3.sat == result:
  print('Allowed')
else:
  print('Denied')
``` 
This doesn't seem very useful, but it is important for conformance testing: it enables us to validate that our access control works the same as the real-world system.

## Regexes!

I've spent a whole lot of words on things that *aren't* the title of the post.
It's true, regexes really are the star of the show here; let's dive in!
You may recall that "regex" is a portmanteau of "regular expression", as in an expression defining a regular language — a language recognized by a finite automaton.
Many regex implementations in the wild are more powerful than this nice definition, but Z3 avoids such excesses and supports only the classic regex primitives we all know and love:
  * `a`, matching the character `a` with [`z3.Re('a')`](https://z3prover.github.io/api/html/namespacez3py.html#a3afb38701f4eccb1646b483f035fecff)
  * `ab`, matching `a` then `b` with [`z3.Concat(a,b)`](https://z3prover.github.io/api/html/namespacez3py.html#a78975ede9fab16535e98749a076afb40)
  * `a|b`, matching either `a` or `b` with [`z3.Union(a,b)`](https://z3prover.github.io/api/html/namespacez3py.html#aa4aab21f5f75b00c0138a8bcd917bf1c)
  * `r?`, matching zero or one `r`s with [`z3.Option(r)`](https://z3prover.github.io/api/html/namespacez3py.html#ac19f6cfafaa76cb77a632b12ee38f9b2)
  * `r*`, matching zero or more `r`s with [`z3.Star(r)`](https://z3prover.github.io/api/html/namespacez3py.html#a2e4d2185ba57c8bc794196716aea16eb)
  * `r+`, matching one or more `r`s with [`z3.Plus(r)`](https://z3prover.github.io/api/html/namespacez3py.html#acba63a624fd58e55af0d534b35812f66)
  * `r{m,n}`, matching `m` to `n` `r`s with [`z3.Loop(r,m,n)`](https://z3prover.github.io/api/html/namespacez3py.html#a774625367b9e3cd09b5da2504c0129f8)
  * `[m-n]`, matching a range of characters with [`z3.Range(m,n)`](https://z3prover.github.io/api/html/namespacez3py.html#a4ab30fd4dbb8a254f9d88305fde897d3)

Z3 supports unicode, so regexes matching unbounded sets of codepoints like `.` or `[^abc]` can be built up from `z3.Range`, `z3.Union`, and some other useful functions:
  * [`z3.AllChar()`](https://z3prover.github.io/api/html/namespacez3py.html#a5452ff43e6d9be298c6b7b290ec2387c) matches all single codepoints
  * [`z3.Full()`](https://z3prover.github.io/api/html/namespacez3py.html#ae1c51b96a50ed5da642d0b9b15d1e66e) matches all strings
  * [`z3.Empty()`](https://z3prover.github.io/api/html/namespacez3py.html#a0457f7cdd6d514401b3fb26f0de6201c) matches no strings
  * [`z3.Intersect(r1, r2)`](https://z3prover.github.io/api/html/namespacez3py.html#a770aa24dbd7284ed78d8d40afd377c15) matches strings matched by both `r1` and `r2`
  * [`z3.Complement(r)`](https://z3prover.github.io/api/html/namespacez3py.html#ad72e9f1361ab533e619bd8d7f1c961bf) matches any string except those matched by `r`

You can use these functions to build up a regex in Z3 — then what?
Well, other than ["using the space shuttle to taxi around the parking lot"](https://twitter.com/AlmheiriAE/status/1020052926029533185) and checking whether a string matches your regex with [`z3.InRe(s,r)`](https://z3prover.github.io/api/html/namespacez3py.html#ae2af603e2d945fc55e68c1e9a6e01ed8) you can check whether two regexes are equivalent!
For example, the regexes `(ab)*a` and `a(ba)*`:
```python
import z3

a = z3.Re('a')
b = z3.Re('b')
r1 = z3.Concat(a, z3.Star(z3.Concat(b, a))) # a(ba)*
r2 = z3.Concat(z3.Star(z3.Concat(a, b)), a) # (ab)*a
solver = z3.Solver()
solver.add(z3.Distinct(r1, r2))
result = solver.check()
if z3.sat == result:
  print(f'Not equivalent; counterexample: {solver.model()}')
else:
  print('Equivalent!')
```
The solver will return `z3.unsat`, which means the regexes are equivalent.
At first glance this seems backward; why does an unsatisfiability result after asserting that the regexes are distinct mean the regexes are equivalent?
This is one of those things where it's linguistically annoying to explain, so just mull it over for a bit if you want; it helps to know that `z3.Distinct(a,b)` is equivalent to `a != b` or `z3.Not(a == b)`, so what you're asking the solver amounts to "does there exist some assignment of values to variables such that `a` evaluates to a different value than `b`?"
If the solver answers that no, no such values exist, then `a` and `b` must be equivalent.
This double-negative sandwiching a quantifier is understandably difficult to wrap your head around; it's easy and perfectly workable to just memorize the convention.

It's a bit clunky to assemble your regex through a series of Z3 function calls, so I've come up with something better.
Python has a built-in regex parser in the `sre_parse` module.
I've written [a function](https://github.com/gravitational/rbac-linter/blob/2e64c6e437f2309cbd16b4859bb39d6b73807360/role_analyzer.py#L313) translating the output of that parser to a Z3 regex formula.
The first part of our above program becomes:
```python
from role_analyzer import regex_to_z3_expr
import sre_parse

r1 = regex_to_z3_expr(sre_parse.parse('(ab)*a'))
r2 = regex_to_z3_expr(sre_parse.parse('a(ba)*'))
```
I later found another [blog post on regexes in Z3](https://medium.com/@pschanely/modeling-python-regular-expressions-with-z3-fe391b7ee24) by Phillip Schanely who sadly had already implemented a very similar function!
Perhaps it should be added to the Z3 Python bindings themselves.

## Regexes in roles

Let's put it all together.
Consider a role giving access to nodes running `fooapp` in a certain set of datacenters:
```yaml
allow:
  node_labels:
    location: 'us-east-[\w]+'
    running: 'fooapp'
```
We can represent this role in Z3 as follows (note that this role has no constraints involving user traits):
```python
import z3
from role_analyzer import regex_to_z3_expr
import sre_parse

node_location = z3.String('node_location')
node_running = z3.String('node_running')
location_regex = regex_to_z3_expr(sre_parse.parse('us-east-[\w]+'))

role = z3.And(z3.InRe(node_location, location_regex), node_running == z3.StringVal('fooapp'))
```
We're using the [`z3.InRe`](https://z3prover.github.io/api/html/namespacez3py.html#ae2af603e2d945fc55e68c1e9a6e01ed8) function so our regex becomes a constraint on a string variable: whatever value the variable takes on, it must match that regex.

That's pretty much it!
At a high level, that's how you build an analysis engine for a RBAC system in Z3.

## Complications

There are, of course, many additional issues you need to handle to make the step from this blog post to a real-world RBAC analysis system.
Here I'll go over a few of them.

We've been cheating a bit in our representation of roles, specifically the string variables.
Instead of giving each user trait or node label a separate variable, you probably want to model them all as a map from strings to strings.
Z3 has the concept of uninterpreted functions, where you can apply constraints over functions mapping from some domain type (possibly multiple) to a range type.
The solver then generates an actual implementation of the function satisfying your constraints — pretty neat!
Of course, the generated functions usually make very little sense to humans as written so don't expect to be unemployed by Z3 anytime in the near future.
Anyway, I made heavy use of constraints over uninterpreted function in my implementation of the Teleport RBAC analysis engine.
Of course, there are many, many ways to model things in Z3 so it's possible you'll find something that works even better — maybe even just a whole bunch of variables, like in this post!

In Teleport RBAC, nodes must possess labels corresponding to all constraints in a role.
They are otherwise rejected by default: if a role has a constraint over the `location` label, and a node doesn't provide any value for the `location` label, the role will not allow access to the node regardless of any of the other constraints or labels.
This means you have to model the required set of label keys in Z3 somehow.
Z3 actually has a `z3.Set` sort, so you'd think this would be easy!
You can indeed use constraints over `z3.Set`, but it's quite heavyweight; I opted for constraints over an uninterpreted function from strings to bools.
That isn't quite the end of it.
This approach works for comparing two roles, but fails when checking whether a role admits a user to a node for conformance testing.
The reason is quite funny: if you have a large set of constraints over what strings need to be in a set, the solver will just use the set containing all strings!
In terms of uninterpreted functions, this is just the function that always returns true.
So you also have to write constraints about what strings are *not* in the set.
However, it's possible this confusion could be alleviated by using [a different representation](https://stackoverflow.com/a/70278814/2852699) for sets.

Teleport RBAC includes constraints beyond regexes, for example functions on strings like `email.local` or `regex.replace` or even string interpolation. 
These were handled with quantification over the set of all strings.
This introduces an area of possible performance cliffs, but it's likely that any two equivalent constraints using these functions will be written exactly the same way so it might not be an issue.

## Conclusion

Hopefully this post gave you some insight into how you might use Z3 to analyze not just access control systems, but other types of systems as well!
Learning Z3 expanded my perception of what it was possible for programs to do.
The tool developed for Teleport will first be put to use linting sets of RBAC rules to check for redundancies; it could also be extended to ensure various global security constraints are satisfied.
If you're interested in learning more the tool is open-sourced [here](https://github.com/gravitational/rbac-linter), Teleport documentation is [here](https://goteleport.com/docs/), and the online textbook *Programming Z3* is [here](https://theory.stanford.edu/~nikolaj/programmingz3.html).
