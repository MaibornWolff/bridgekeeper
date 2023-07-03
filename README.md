# Bridgekeeper

> "What... is your favorite policy language?"
>
> "Rego. (shocked) No... Pythoooooon!!!"
>
> -- Based loosely on Monty Python and the Holy Grail

Bridgekeeper helps you to enforce policies in your kubernetes cluster by providing a simple declarative way to define policies using the python programming language. Whenever resources are created or updated matching policies will be evaluated and if a policy is violated the resource will be rejected.

From a technical perspective bridgekeeper acts as a kubernetes [admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/). For every admission request that it gets it will check all registered policies if any match the resource of the request and if yes the policy will be evaluated and based on the result the admission request will be allowed or rejected.

Bridgekeeper is similar to and inspired by [OPA gatekeeper](https://github.com/open-policy-agent/gatekeeper). It was born out of the idea to make gatekeeper simpler and use python instead of rego (because we love python) as the policy language.

## User Guide

### Installation Requirements

* A kubernetes cluster (version >= 1.24) with cluster-admin permissions
* Helm

### Installation

If you want to use a released version:

1. Add the helm repo: `helm repo add bridgekeeper https://maibornwolff.github.io/bridgekeeper/`
2. Install the chart: `helm install --namespace bridgekeeper --create-namespace bridgekeeper bridgekeeper/bridgekeeper`

If you want to use the current master version from git:

1. Install the chart: `helm install --namespace bridgekeeper --create-namespace bridgekeeper ./charts/bridgekeeper`

### Configuration

Bridgekeeper has a number of options to configure behaviour. They can be set via helm values:

```yaml
replicaCount: 1  # Number of instances of bridgekeeper to run, should be >1 for production setups

installCRDs: true  #  By default the helm chart installs the CRD, set to false if you want to do this in a separate workflow

bridgekeeper:
  # namespaces to ignore for validation, you should add the namespace you install bridgekeeper in
  ignoreNamespaces:
    - kube-system
    - kube-public
    - kube-node-lease
  # If set to true any requests in non-ignored namespaces will fail while bridgekeeper is not available (sets failure policy to "Fail")
  strictAdmission: false
  audit: 
    # Set this to true if you want bridgekeeper to run regular audits, if enabled you should have replicaCount: 1
    enabled: false
    # Audit interval in seconds
    interval: 600
```

### Writing policies

Bridgekeeper uses a custom resource called Policy to manage rules. A policy consists of a target that describes what kubernetes resources are to be validated by the policy and a rule script written in python.

Below is a minimal example:

```yaml
apiVersion: bridgekeeper.maibornwolff.de/v1alpha1
kind: Policy
metadata:
  name: foobar
spec:
  target:
    matches:
      - apiGroup: apps
        kind: "Deployment"
  rule:
    python: |
      def validate(request):
        return False, "You don't want to deploy anything today"
```

The policy spec has the following fields:

* `audit`: If set to true and bridgekeeper is started with the audit feature enabled this policy will be checked during audit runs (see also next section).
* `enforce`: If set to false a policy violation will be logged but the request will still be allowed. Defaults to true. Can be used to safely test policies.
* `target.matches`: A list of one or more match parameters consisting of `apiGroup` and `kind`. Wildcards can be used as `"*"`, if the resource has no API group (e.g. namespaces) use an empty string `""`.
* `target.namespaces`: An optional list of strings, if specified only resources from one of these namespaces are matched, only this or `target.excludedNamespaces` can be specified, not both
* `target.excludedNamespaces`: An optional list of strings, if specified resources from one of these namespaces are not matched, only this or `target.namespaces` can be specified, not both
* `rule.python`: An inline python script representing the rule code.

The rule script must have a function called `validate` that gets exactly one parameter that contains the [AdmissionRequest](https://github.com/kubernetes/api/blob/master/admission/v1/types.go#L40)) as a python structure as `json.loads` would produce it. The function must return one of the following:

* A single boolean that represents the result (true means resource is accepted, false means rejected)
* A tuple of boolean and string: The string is an optional reason for the rejection that will be sent to the caller
* A tuple of boolean, string and object: The object is the mutated version of the input object (`request["object"]`).

If the python code is not valid, raises an exception or the return value does not match any of the above it will be treated as a rejection.

If the code returns a mutated object bridekeeper will calculate the diff between the input and output objects and return it with the admission response so that Kubernetes can apply the patch to the object.

You can use the entire python feature set and standard library in your script (so stuff like `import re` is possible). Using threads or accessing the filesystem should not be done and might be prohibited in the future. The official bridgekeeper docker image includes the [python kubernetes library](https://github.com/kubernetes-client/python) so you can use that in policies to query the Kubernetes API. Depending on which resources you want to access you might need to assign bridgekeeper an additional ClusterRole (can be done via the helm chart by setting `serviceAccount.extraClusterRole`).

You can find a more useful example under [example/policy.yaml](example/policy.yaml) that denies deployments that use a docker image with a `latest` tag. Try it out using the following steps:

1. `kubectl apply -f example/policy.yaml` to create the policy
2. `kubectl apply -f example/deployment-error.yaml` will yield an error because the docker image is referenced using the `latest` tag
3. `kubectl apply -f example/deployment-ok.yaml` will be accepted because the docker image tag uses a specific version

Policies are not namespaced and apply to the entire cluster unless `target.namespaces` or `target.excludedNamespaces` are used to filter namespaces. To completely exclude a namespace from bridgekeeper label it with `bridgekeeper/ignore`. If you use the helm chart to install bridgekeeper you can set the option `bridgekeeper.ignoreNamespaces` to a list of namespaces that should be labled and it will be done during initial install (by default it will label the `kube-*` namespaces).

### Mutations

Aside from deciding if an object is allowed or should be rejected policies can also modify (called mutate in Kubernetes speak) the object prior to it being applied in kubernetes. Common examples are automatically adding proxy information to pods or adding labels to deployments to help with cost distribution.

Mutations are implemented very lightweight in bridgekeeper. Instead of generating patches a rule can simply modify the object (which is just a nested python structure) and return that object along with the admission decision. Bridgekeeper will take care to generate the JSON patches that are needed for Kubernetes.

To mutate the object the validate function must return a tuple of boolean, string, object/dict. If the object is rejected the mutations are ignored. If you do not want to return a reason just return `None`.

An example that adds a label to each deployment can be found under [example/mutate-add-label.yaml](example/mutate-add-label.yaml)

### Auditing

Bridgekeeper has an audit feature that periodically checks if any existing objects violate policies. This is useful to check objects that were created before the policy was installed.

There are two ways to run the audits:

* Embedded in the main bridgekeeper process. This should only be used if you run bridgekeeper with only one replica as otherwise all replicas would run the audit.
* As a separate container run as a CronJob. This requires a Prometheus Pushgateway instance to collect metrics but can be used with multiple replicas enabled.

To configure one of the modes in the helm chart use these options:

```yaml
bridgekeeper:
  # Embedded mode
  audit: 
    # Set this to true if you want bridgekeeper to run regular audits, replicaCount should be set to 1
    enabled: false
    # Audit interval in seconds
    interval: 600
  # Separate CronJob
  audit_cronjob:
    # Set this to true if you want bridgekeeper to run regular audits as a cronjob (only this or audit.enabled should be set to true)
    enabled: false
    # Set to true to have bridgekeeper update the Policy object status with a list of violations
    update_status: true
    # Cron schedule when to run the audits
    schedule: "*/30 * * * *"  # default: every 30 minutes
    # URL of the Prometheus Pushgateway to send metrics to, leave empty to disable. Example: http://pushgateway.default.svc.cluster.local:9091
    pushgateway_url: ""
    # CPU and memory resource requests and limits, if not set defaults to that of main brigekeeper deployment
    resources: {}
```

To include a policy in the audit run set the `spec.audit` field to `true`. The namespace include/exclude lists of the policies and the `bridgekeeper/ignore` label on namespaces are honored during audit runs. The results of the run will be stored in the status of the policy with a list of objects that violate the policy and the provided reason if any.

If run in embedded mode or with a configured pushgateway url bridgekeeper will provide metrics for the audit run to Prometheus. These can for example be used to create a Grafana dashboard displaying violations. The relevant metrics are `bridgekeeper_audit_checked_objects` and `bridgekeeper_audit_violations` which both have labels `namespace` and `policy`. If you want to monitor that audit runs are done successfully you can check the metrics `bridgekeeper_audit_last_run_successful` (set to 1 if last run was successful) and `bridgekeeper_audit_last_run_timestamp_seconds` which gives the time in seconds since unix epoch when audit was last run.

A single audit run can also be launched locally running the binary with `bridgekeeper audit`. This will connect to the kubernetes cluster defined by the currently active kubernetes context (as kubectl would use it), read in all existing policies and perform an audit run. All objects that violate a policy are printed on the console as output, this can be disabled by providing `--silent`. By adding the `--status` flag the policy status will also be updated with the violations.

Note that any mutations returned by the rules are ignored in audit mode and no objects are modified.

## Developer Guide

This service is written in Rust and uses [kube-rs](https://github.com/clux/kube-rs) as kubernetes client, [rocket](https://rocket.rs/) as web framework and [PyO3](https://pyo3.rs/) as python bindings.

### Requirements

* Current stable Rust (version >=1.60) with cargo
* Python >= 3.8 with shared library (pyenv by default does not provide a shared library, install with `PYTHON_CONFIGURE_OPTS="--enable-shared" pyenv install <version>` to enable it)
* A kubernetes cluster (version >= 1.24) with cluster-admin permissions, this guide assumes a local [k3s](https://k3s.io/) cluster set up with [k3d](https://k3d.io/)
* kubectl, helm
* Tested only on linux, should also work on MacOS

### Start service locally

1. Compile binary: `cargo build`
2. Generate certificates and install webhook: `cargo run -- init --local host.k3d.internal:8081`
3. Install CRD: `cargo run -- gencrd -f - | kubectl apply -f -`
4. Launch bridgekeeper: `cargo run -- server --cert-dir .certs --local host.k3d.internal:8081`

After you are finished, run `cargo run -- cleanup --local` to delete the webook.

### Development cycle

As long as you do not change the schema of the policies you can just recompile and restart the server without having to reinstall any of the other stuff (certificate, webhook, policies).
If you change the schema of the CRD (via `src/crd.rs`) you need to regenerate the CRD yaml in the helm chart by running `cargo run -- gencrd`.

### Test cluster deployment

1. Build docker image: `docker build . -t bridgekeeper:dev`
2. Upload docker image into cluster: `k3d image import bridgekeeper:dev`
3. Deploy helm chart: `helm upgrade --install --namespace bridgekeeper --create-namespace bridgekeeper ./charts/bridgekeeper --set image.repository=bridgekeeper --set image.tag=dev`

## Planned features

* Give rules access to existing objects of the same type (to do e.g. uniqueness checks)
