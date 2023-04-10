import os
import subprocess
import sys
import textwrap
import json


def apply(path):
    return subprocess.run(f"kubectl apply -f {path}", shell=True, capture_output=True, env=os.environ)

def delete(path):
    return subprocess.run(f"kubectl delete -f {path}", shell=True, capture_output=True, env=os.environ)

def audit():
    result = subprocess.run("kubectl exec -it -n bridgekeeper deploy/bridgekeeper -- /usr/local/bin/bridgekeeper audit --json --silent", shell=True, capture_output=True, env=os.environ)
    result.check_returncode()
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except:
        print("X audit results could not be parsed")
        print(textwrap.indent(result.stdout.decode("utf-8"), 4 * ' '))
        return []

def diff(path):
    return subprocess.run(f"kubectl diff -f {path}", shell=True, capture_output=True, env=os.environ)


failed = False

# Check normal apply mode
section = "apply"
# Apply policies
policies = list()
for policy in os.listdir("apply/policies"):
    apply(os.path.join(f"apply/policies/{policy}")).check_returncode()
    policies.append(policy)

# Run through test files
for test in os.listdir("apply/test_files"):
    name = test.replace(".yaml", "")
    result = apply(os.path.join(f"apply/test_files/{test}"))
    expect_ok = test.endswith("-ok.yaml")
    if result.returncode == 0:
        if expect_ok:
            print(f"Y {section}/{name}")
        else:
            failed = True
            print(f"X {section}/{name}")
    else:
        if expect_ok:
            failed = True
            print(f"X {section}/{name}")
            print(textwrap.indent(result.stderr.decode("utf-8"), 4 * ' '))
        else:
            print(f"Y {section}/{name}")
    delete(os.path.join(f"apply/test_files/{test}"))

# Delete policies
for policy in policies:
    delete(os.path.join(f"apply/policies/{policy}")).check_returncode()


# Check audit mode
section = "audit"
# Create audit objects
for test in os.listdir("audit/test_files"):
    apply(os.path.join(f"audit/test_files/{test}")).check_returncode()

# Create audit policies
for policy in os.listdir("audit/policies"):
    apply(os.path.join(f"audit/policies/{policy}")).check_returncode()

# Do audit run
violations = audit()
def check_for_violation(name):
    for violation in violations:
        if violation["target"]["name"] == name:
            return True
    return False

for test in os.listdir("audit/test_files"):
    name = test.replace(".yaml", "")
    if check_for_violation(name):
        print(f"Y {section}/{name}")
    else:
        failed = True
        print(f"X {section}/{name}")

# Cleanup
for test in os.listdir("audit/test_files"):
    delete(os.path.join(f"audit/test_files/{test}"))
for policy in os.listdir("audit/policies"):
    delete(os.path.join(f"audit/policies/{policy}"))


# Test mutations
section = "mutate"
policies = list()
for policy in os.listdir("mutate/policies"):
    apply(os.path.join(f"mutate/policies/{policy}")).check_returncode()
    policies.append(policy)

# Run through test files
for test in os.listdir("mutate/test_files"):
    name = test.replace(".yaml", "")
    if name.endswith("-mutated"):
        continue
    result = apply(os.path.join(f"mutate/test_files/{test}"))
    if result.returncode != 0:
        failed = True
        print(f"X {section}/{name}")
        print(textwrap.indent(result.stderr.decode("utf-8"), 4 * ' '))

# Delete policies
for policy in policies:
    delete(os.path.join(f"mutate/policies/{policy}")).check_returncode()

# Check for diffs, can only be done after deleting policies otherwise diff would be compromised by possible mutations of the policies
for test in os.listdir("mutate/test_files"):
    if not test.endswith("-mutated.yaml"):
        continue
    name = test.replace("-mutated.yaml", "")
    result = diff(os.path.join(f"mutate/test_files/{test}"))
    if result.returncode == 0:
        print(f"Y {section}/{name}")
    else:
        failed = True
        print(f"X {section}/{name}")
        print(textwrap.indent(result.stdout.decode("utf-8"), 4 * ' '))
    delete(os.path.join(f"mutate/test_files/{test}"))


# Verify invalid policies
section = "invalid-policies"
for policy in os.listdir("invalid/policies"):
    name = policy.replace(".yaml", "")
    result = apply(os.path.join(f"invalid/policies/{policy}"))
    if result.returncode == 0:
        print(f"X {section}/{name}")
        failed = True
        delete(os.path.join(f"invalid/policies/{policy}"))
    else:
        print(f"Y {section}/{name}")


# Finalize
if failed:
    print("Tests failed")
    sys.exit(1)
else:
    print("Tests successful")
    sys.exit(0)
