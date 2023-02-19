use crate::crd::{Policy, PolicyStatus, Violation};
use crate::events::init_event_watcher;
use crate::manager::Manager;
use crate::module::{ModuleStore, ModuleStoreRef, ModuleInfo};
use crate::policy::{load_policies_from_file, PolicyInfo, PolicyStore, PolicyStoreRef};
use crate::util::error::{kube_err, load_err, BridgekeeperError, Result};
use crate::util::k8s::{
    find_k8s_resource_matches, list_with_retry, namespaces, patch_status_with_retry,
};
use argh::FromArgs;
use k8s_openapi::chrono::{DateTime, Utc};
use kube::Resource;
use kube::{
    api::{Api, DynamicObject, ListParams, Patch, PatchParams},
    core::ApiResource as KubeApiResource,
    Client, CustomResourceExt,
};
use lazy_static::lazy_static;
use prometheus::proto::MetricFamily;
use prometheus::{
    register_counter, register_gauge, register_gauge_vec, Counter, Encoder, Gauge, GaugeVec,
};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::time::SystemTime;
use tokio::task;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

lazy_static! {
    static ref NUM_AUDIT_RUNS: Counter =
        register_counter!("bridgekeeper_audit_runs", "Number of audit runs.")
            .expect("creating metric always works");
    static ref NUM_CHECKED_OBJECTS: GaugeVec = register_gauge_vec!(
        "bridgekeeper_audit_checked_objects",
        "Number of objects checked in last audit run.",
        &["policy", "namespace"]
    )
    .expect("creating metric always works");
    static ref NUM_VIOLATIONS: GaugeVec = register_gauge_vec!(
        "bridgekeeper_audit_violations",
        "Number of violations in last audit run.",
        &["policy", "namespace"]
    )
    .expect("creating metric always works");
    static ref NUM_CHECKED_POLICIES: Gauge = register_gauge!(
        "bridgekeeper_audit_policies",
        "Number of policies checked in last audit run."
    )
    .expect("creating metric always works");
    static ref TIMESTAMP_LAST_RUN: Gauge = register_gauge!(
        "bridgekeeper_audit_last_run_timestamp_seconds",
        "Time in seconds since unix epoch when audit was last run."
    )
    .expect("creating metric always works");
    static ref LAST_AUDIT_RUN_SUCCESSFUL: Gauge = register_gauge!(
        "bridgekeeper_audit_last_run_successful",
        "Shows if last audit run was successful (1=yes, 0=no)."
    )
    .expect("creating metric always works");
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "audit")]
/// Audit existing policies
pub struct Args {
    /// update policy status with list of violations
    #[argh(switch)]
    status: bool,
    /// do not print violations
    #[argh(switch, short = 's')]
    silent: bool,
    /// audit all policies, even those marked as not audit
    #[argh(switch)]
    all: bool,
    /// load policies from file instead of from kubernetes
    #[argh(option, short = 'f')]
    file: Vec<String>,
    /// produce json output with all violations
    #[argh(switch)]
    json: bool,
}

#[derive(Serialize)]
struct EvaluationTarget {
    api_group: String,
    kind: String,
    namespace: Option<String>,
    name: String,
}

impl EvaluationTarget {
    pub fn new(resource: &KubeApiResource, object: &DynamicObject) -> EvaluationTarget {
        let meta = object.meta();
        EvaluationTarget {
            api_group: resource.group.clone(),
            kind: resource.kind.clone(),
            namespace: meta.namespace.clone(),
            name: meta.name.clone().expect("Each object has a name"),
        }
    }

    pub fn identifier(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.api_group,
            self.kind,
            self.namespace.clone().unwrap_or("-".to_string()),
            self.name
        )
    }
}

#[derive(Serialize)]
struct AuditViolation {
    policy: String,
    target: EvaluationTarget,
    message: Option<String>,
}

impl AuditViolation {
    pub fn new(
        target: EvaluationTarget,
        policy: &String,
        message: Option<String>,
    ) -> AuditViolation {
        AuditViolation {
            policy: policy.clone(),
            target,
            message,
        }
    }
}

struct Auditor {
    k8s_client: Client,
    policies: PolicyStoreRef,
    modules: ModuleStoreRef,
    //event_sender: EventSender,
}

impl Auditor {
    pub fn new(
        client: Client,
        policies: PolicyStoreRef,
        modules: ModuleStoreRef,
        //event_sender: EventSender,
    ) -> Auditor {
        pyo3::prepare_freethreaded_python();
        Auditor {
            k8s_client: client,
            policies,
            modules,
            //event_sender,
        }
    }

    async fn audit_policies(
        &self,
        print_violations: bool,
        update_status: bool,
        all: bool,
    ) -> Result<Vec<AuditViolation>> {
        let mut violations = Vec::new();
        let mut policies = Vec::new();
        let mut modules = HashMap::new();
        // While holding the lock only collect the policies or modules, directly auditing them would make the future of the method not implement Send which breaks the task spawn
        {
            let policy_store = self.policies.lock().expect("lock failed. Cannot continue");
            for policy in policy_store.get_objects().values() {
                if all || policy.policy.audit.unwrap_or(false) {
                    policies.push(policy.clone());
                }
            }
        }

        {
            let module_store = self.modules.lock().expect("lock failed. Cannot continue");
            modules.extend(module_store.get_objects());
        }

        for policy in policies.iter() {
            match self
                .audit_policy(policy, &modules, print_violations, update_status)
                .await
            {
                Ok(mut result) => {
                    violations.append(&mut result);
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        let now: DateTime<Utc> = SystemTime::now().into();
        NUM_CHECKED_POLICIES.set(policies.len() as f64);
        NUM_AUDIT_RUNS.inc();
        TIMESTAMP_LAST_RUN.set(now.timestamp() as f64);
        Ok(violations)
    }

    async fn audit_policy(
        &self,
        policy: &PolicyInfo,
        modules: &HashMap<String, ModuleInfo>,
        print_violations: bool,
        update_status: bool,
    ) -> Result<Vec<AuditViolation>> {
        if print_violations {
            println!("Auditing policy {}", policy.name);
        }

        let mut module_code = String::new();

        if let Some(used_modules) = &policy.policy.rule.modules {
            for module_name in used_modules.iter() {
                match modules.get(module_name) {
                    Some(module_info) => {
                        module_code.push_str(&module_info.module.python);
                        module_code.push_str("\n");
                    },
                    None => {
                        log::warn!("Could not find module '{}'", module_name);
                    }
                };
            }
        }

        let (valid, reason) = crate::evaluator::validate_policy(&policy.name, &policy.policy, &module_code);
        if !valid {
            if print_violations {
                println!(
                    "Failed to validate policy: {}",
                    reason.unwrap_or_else(|| "N/A".to_string())
                );
            }
            return Err(load_err("Policy is invalid"));
        }
        // collect all matching k8s resources
        let namespaces = namespaces(self.k8s_client.clone()).await?;
        let mut matched_resources: Vec<(KubeApiResource, bool)> = Vec::new();
        for target_match in policy.policy.target.matches.iter() {
            let mut result = find_k8s_resource_matches(
                &target_match.api_group,
                &target_match.kind,
                &self.k8s_client,
            )
            .await?;
            matched_resources.append(&mut result);
        }

        // audit all objects
        let mut violations = Vec::new();

        for (resource_description, namespaced) in matched_resources.iter() {
            if *namespaced {
                for namespace in namespaces.iter() {
                    if policy.is_namespace_match(namespace) {
                        // Initialize metrics
                        let _ = NUM_VIOLATIONS.get_metric_with_label_values(&[
                            policy.name.as_str(),
                            namespace.as_str(),
                        ]);
                        let _ = NUM_CHECKED_OBJECTS.get_metric_with_label_values(&[
                            policy.name.as_str(),
                            namespace.as_str(),
                        ]);
                        // Retrieve objects
                        let api = Api::<DynamicObject>::namespaced_with(
                            self.k8s_client.clone(),
                            namespace,
                            resource_description,
                        );
                        let objects = list_with_retry(&api, ListParams::default())
                            .await
                            .map_err(kube_err)?;
                        for object in objects {
                            let target = EvaluationTarget::new(resource_description, &object);
                            let (result, message, _patch) =
                                crate::evaluator::evaluate_policy_audit(policy, object, &module_code);
                            NUM_CHECKED_OBJECTS
                                .with_label_values(&[policy.name.as_str(), namespace.as_str()])
                                .inc();
                            if !result {
                                NUM_VIOLATIONS
                                    .with_label_values(&[policy.name.as_str(), namespace.as_str()])
                                    .inc();
                                violations.push(AuditViolation::new(
                                    target,
                                    &policy.name,
                                    message.clone(),
                                ));
                            }
                        }
                    }
                }
            } else {
                // Initialize metrics
                let _ = NUM_VIOLATIONS.get_metric_with_label_values(&[policy.name.as_str(), ""]);
                let _ =
                    NUM_CHECKED_OBJECTS.get_metric_with_label_values(&[policy.name.as_str(), ""]);
                // Retrieve objects
                let api =
                    Api::<DynamicObject>::all_with(self.k8s_client.clone(), resource_description);
                let objects = match list_with_retry(&api, ListParams::default()).await {
                    Ok(objects) => objects,
                    Err(err) => return Err(BridgekeeperError::KubernetesError(format!("{}", err))),
                };
                for object in objects {
                    let target = EvaluationTarget::new(resource_description, &object);
                    let (result, message, _patch) =
                        crate::evaluator::evaluate_policy_audit(policy, object, &module_code);
                    NUM_CHECKED_OBJECTS
                        .with_label_values(&[policy.name.as_str(), ""])
                        .inc();
                    if !result {
                        NUM_VIOLATIONS
                            .with_label_values(&[policy.name.as_str(), ""])
                            .inc();
                        violations.push(AuditViolation::new(target, &policy.name, message.clone()));
                    }
                }
            }
        }
        if print_violations {
            for violation in violations.iter() {
                let message = match violation.message.as_ref() {
                    Some(reason) => format!(": {}", reason),
                    None => String::new(),
                };
                println!(
                    "{} violates policy '{}'{}",
                    violation.target.identifier(),
                    policy.name,
                    message
                );
            }
        }
        // Attach audit results to policy status
        if update_status {
            self.report_result(policy.name.clone(), &violations).await?;
        }
        Ok(violations)
    }

    async fn report_result(&self, name: String, results: &Vec<AuditViolation>) -> Result<()> {
        let api: Api<Policy> = Api::all(self.k8s_client.clone());
        let mut status = PolicyStatus::new();
        let mut audit_status = status
            .audit
            .as_mut()
            .expect("Newly created PolicyStatus always has an audit object");
        let now: DateTime<Utc> = SystemTime::now().into();
        audit_status.timestamp = Some(now.to_rfc3339());

        let mut violations = Vec::new();
        for result in results {
            let violation = Violation {
                identifier: result.target.identifier(),
                message: result
                    .message
                    .clone()
                    .unwrap_or_else(|| String::from("N/A")),
            };
            violations.push(violation);
        }
        audit_status.violations = Some(violations);

        let crd_resource = Policy::api_resource();
        let new_status = Patch::Merge(json!({
            "apiVersion": crd_resource.api_version,
            "kind": crd_resource.kind,
            "status": status,
        }));
        let ps = PatchParams::default();
        match patch_status_with_retry(&api, &name, &ps, &new_status).await {
            Ok(_) => Ok(()),
            Err(err) => Err(BridgekeeperError::KubernetesError(format!("{}", err))),
        }
    }
}

pub async fn run(args: Args) {
    // First reset metrics
    NUM_VIOLATIONS.reset();
    NUM_CHECKED_OBJECTS.reset();
    NUM_CHECKED_POLICIES.set(0.0);
    LAST_AUDIT_RUN_SUCCESSFUL.set(0.0);
    // Initialize
    let client = kube::Client::try_default()
        .await
        .expect("Fail early if kube client cannot be created");
    let policies = PolicyStore::new();
    let modules = ModuleStore::new();
    let event_sender = init_event_watcher(&client);
    // Load policies either from kubernetes or from file
    if !args.file.is_empty() {
        for filename in args.file.iter() {
            load_policies_from_file(policies.clone(), filename).expect("failed to load policy");
        }
    } else {
        let mut manager = Manager::new(client.clone(), policies.clone(), modules.clone(), event_sender.clone());
        manager
            .load_existing_policies()
            .await
            .expect("Could not load existing policies");
        manager
            .load_existing_modules()
            .await
            .expect("Could not load existing policies");
    }
    // Run audit
    let auditor = Auditor::new(client, policies, modules);
    match auditor
        .audit_policies(!args.silent, args.status, args.all)
        .await
    {
        Ok(violations) => {
            info!("Finished audit");
            LAST_AUDIT_RUN_SUCCESSFUL.set(1.0);
            if args.json {
                json_result(violations);
            }
        }
        Err(err) => error!("Audit failed: {}", err),
    };

    // Push metrics
    let metric_families = prometheus::gather();
    push_metrics(metric_families).await;
}

fn json_result(violations: Vec<AuditViolation>) {
    let json = serde_json::to_string(&violations).unwrap();
    println!("{}", json);
}

pub async fn launch_loop(client: kube::Client, policies: PolicyStoreRef, modules: ModuleStoreRef, interval: u32) {
    task::spawn(async move {
        let auditor = Auditor::new(client, policies, modules);
        loop {
            sleep(Duration::from_secs(interval as u64)).await;
            info!("Starting audit run");
            match auditor.audit_policies(false, true, false).await {
                Ok(_) => info!("Finished audit run"),
                Err(err) => error!("Audit run failed: {}", err),
            }
        }
    });
}

async fn push_metrics(metric_families: Vec<MetricFamily>) {
    let url = match std::env::var("PUSHGATEWAY_URL") {
        Ok(url) => {
            if url.is_empty() {
                return;
            }
            url
        }
        Err(_) => return,
    };
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    let body = String::from_utf8(buffer).unwrap();

    let client = reqwest::Client::new();
    let result = client
        .put(&format!("{}/metrics/job/bridgekeeper", url))
        .body(body)
        .send()
        .await;
    if let Err(err) = result {
        error!("Failed to send metrics to pushgateway at {}: {}", url, err);
    }
}
