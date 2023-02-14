# Functional tests

This folder contains scripts and test files for functional tests.

The tests are split into several sections:

* `apply`: Tests if a kubernetes spec can be applied with a policy active
* `audit`: Tests if the audit mode discovers certain violations
* `invalid`: Tests if invalid policies are correctly rejected by bridgekeeper
* `mutate`: Tests if mutations defined in a policy are correctly applied

To add a new test:

* For `apply`:
  * Add a policy to `apply/policies` and one or more test files to `apply/test_files`. The names must end in either `-ok.yaml` if the spec should pass or `-error.yaml` if it should be rejected.
* For `audit`:
  * Add a policy to `audit/policies` and one or more test files that have violations to `audit/test_files`. The name of the test spec must be the same as the filename.
* For `invalid`:
  * Add an invalid policy to `invalid/policies`.
* For `mutate`:
  * TODO
