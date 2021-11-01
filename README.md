# rbac-linter
[![Build & Test](https://github.com/gravitational/rbac-linter/actions/workflows/ci.yml/badge.svg)](https://github.com/gravitational/rbac-linter/actions/workflows/ci.yml)

Teleport RBAC analysis using Z3.

## Build & Test

1. Install dependencies:
   * rust/cargo
   * cmake
1. If on Windows, install additional dependencies:
   * [llvm](https://community.chocolatey.org/packages/llvm)
1. `cargo build`
   * Note a clean Z3 build takes 10-15 minutes
1. `cargo test`

## Run Python

1. `pip install -r requirements.txt --user`
1. `python main.py`
