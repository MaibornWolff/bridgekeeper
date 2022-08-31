use crate::crd::{Policy, PolicyStatus, Violation};
use crate::events::init_event_watcher;
use crate::manager::Manager;
use crate::policy::{PolicyInfo, PolicyStore, PolicyStoreRef};
use crate::util::error::{kube_err, BridgekeeperError, Result};
use crate::util::k8s_client::{list_with_retry, patch_status_with_retry};
use argh::FromArgs;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{APIGroup, APIResource};
use k8s_openapi::chrono::{DateTime, Utc};
use kube::{
    api::{Api, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams},
    core::ApiResource as KubeApiResource,
    Client, CustomResourceExt, Resource,
};
use lazy_static::lazy_static;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde_json::json;
use std::time::SystemTime;
use tokio::task;
use tokio::time::{sleep, Duration};

lazy_static! {
    static ref NUM_AUDIT_RUNS: Counter =
        register_counter!("bridgekeeper_audit_runs", "Number of audit runs.")
            .expect("creating metric always works");
    static ref NUM_CHECKED_OBJECTS: Gauge = register_gauge!(
        "bridgekeeper_audit_checked_objects",
        "Number of objects checked in last audit run."
    )
    .expect("creating metric always works");
    static ref NUM_VIOLATIONS: Gauge = register_gauge!(
        "bridgekeeper_audit_violations",
        "Number of violations in last audit run."
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
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "audit")]
/// Audit existing policies
pub struct Args {
    /// update policy status with list of violations
    #[argh(switch)]
    status: bool,
    /// do not print violations
    #[argh(switch, short = 's')]
    silent: bool,
}

struct AuditResult {
    pub processed_objects: usize,
    pub violations: usize,
}

pub struct Auditor {
    k8s_client: Client,
    policies: PolicyStoreRef,
    //event_sender: EventSender,
}

impl Auditor {
    pub fn new(
        client: Client,
        policies: PolicyStoreRef,
        //event_sender: EventSender,
    ) -> Auditor {
        pyo3::prepare_freethreaded_python();
        Auditor {
            k8s_client: client,
            policies,
            //event_sender,
        }
    }

    pub async fn audit_policies(&self, print_violations: bool, update_status: bool) -> Result<()> {
        let mut policies = Vec::new();
        // While holding the lock only collect the policies, directly auditing them would make the future of the method not implement Send which breaks the task spawn
        {
            let policy_store = self.policies.lock().expect("lock failed. Cannot continue");
            for policy in policy_store.policies.values() {
                if policy.policy.audit.unwrap_or(false) {
                    policies.push(policy.clone());
                }
            }
        }
        let mut num_objects = 0;
        let mut num_violations = 0;
        for policy in policies.iter() {
            let result = self
                .audit_policy(policy, print_violations, update_status)
                .await;
            match result {
                Ok(result) => {
                    num_objects += result.processed_objects;
                    num_violations += result.violations;
                }
                Err(err) => return Err(err),
            }
        }
        let now: DateTime<Utc> = SystemTime::now().into();
        NUM_CHECKED_POLICIES.set(policies.len() as f64);
        NUM_CHECKED_OBJECTS.set(num_objects as f64);
        NUM_VIOLATIONS.set(num_violations as f64);
        NUM_AUDIT_RUNS.inc();
        TIMESTAMP_LAST_RUN.set(now.timestamp() as f64);
        Ok(())
    }

    async fn audit_policy(
        &self,
        policy: &PolicyInfo,
        print_violations: bool,
        update_status: bool,
    ) -> Result<AuditResult> {
        // collect all matching k8s resources
        let namespaces = namespaces(self.k8s_client.clone()).await?;
        let mut matched_resources: Vec<(KubeApiResource, bool)> = Vec::new();
        for target_match in policy.policy.target.matches.iter() {
            let mut result = self
                .find_k8s_resource_matches(&target_match.api_group, &target_match.kind)
                .await?;
            matched_resources.append(&mut result);
        }

        // audit all objects
        let mut results = Vec::new();
        let mut num_objects = 0;

        for (resource_description, namespaced) in matched_resources.iter() {
            if *namespaced {
                for namespace in namespaces.iter() {
                    if policy.is_namespace_match(namespace) {
                        let api = Api::<DynamicObject>::namespaced_with(
                            self.k8s_client.clone(),
                            namespace,
                            resource_description,
                        );
                        let objects = list_with_retry(&api, ListParams::default())
                            .await
                            .map_err(kube_err)?;
                        for object in objects {
                            num_objects += 1;
                            let target_identifier =
                                gen_target_identifier(resource_description, &object);
                            let (result, message, _patch) =
                                crate::evaluator::evaluate_policy_audit(policy, object);
                            if !result {
                                results.push((target_identifier, message));
                            }
                        }
                    }
                }
            } else {
                let api =
                    Api::<DynamicObject>::all_with(self.k8s_client.clone(), resource_description);
                let objects = match list_with_retry(&api, ListParams::default()).await {
                    Ok(objects) => objects,
                    Err(err) => return Err(BridgekeeperError::KubernetesError(format!("{}", err))),
                };
                for object in objects {
                    let target_identifier = gen_target_identifier(resource_description, &object);
                    let (result, message, _patch) =
                        crate::evaluator::evaluate_policy_audit(policy, object);
                    if !result {
                        results.push((target_identifier, message));
                    }
                }
            }
        }
        if print_violations {
            for (object, message) in results.iter() {
                let message = match message {
                    Some(reason) => format!(": {}", reason),
                    None => String::new(),
                };
                println!("{} violates policy '{}'{}", object, policy.name, message);
            }
        }
        let num_violations = results.len();
        // Attach audit results to policy status
        if update_status {
            self.report_result(policy.name.clone(), results).await?;
        }
        Ok(AuditResult {
            processed_objects: num_objects,
            violations: num_violations,
        })
    }

    async fn report_result(
        &self,
        name: String,
        results: Vec<(String, Option<String>)>,
    ) -> Result<()> {
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
                identifier: result.0,
                message: result.1.unwrap_or_else(|| String::from("N/A")),
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

    async fn find_k8s_resource_matches(
        &self,
        api_group: &str,
        kind: &str,
    ) -> Result<Vec<(KubeApiResource, bool)>> {
        let mut matched_resources = Vec::new();
        // core api group
        if api_group.is_empty() {
            let versions = self
                .k8s_client
                .list_core_api_versions()
                .await
                .map_err(kube_err)?;
            let version = versions
                .versions
                .first()
                .expect("core api group always has a version");
            let resources = self
                .k8s_client
                .list_core_api_resources(version)
                .await
                .map_err(kube_err)?;
            for resource in resources.resources.iter() {
                if (kind == "*" || resource.kind.to_lowercase() == kind.to_lowercase())
                    && !resource.name.contains('/')
                {
                    matched_resources.push((
                        gen_resource_description(None, resource),
                        resource.namespaced,
                    ));
                }
            }
        } else {
            for group in self
                .k8s_client
                .list_api_groups()
                .await
                .map_err(kube_err)?
                .groups
                .iter()
            {
                if api_group == "*" || group.name.to_lowercase() == api_group.to_lowercase() {
                    let api_version = group
                        .preferred_version
                        .clone()
                        .expect("API Server always has a preferred_version")
                        .group_version;
                    for resource in self
                        .k8s_client
                        .list_api_group_resources(&api_version)
                        .await
                        .map_err(kube_err)?
                        .resources
                        .iter()
                    {
                        if (kind == "*" || resource.kind.to_lowercase() == kind.to_lowercase())
                            && !resource.name.contains('/')
                        {
                            matched_resources.push((
                                gen_resource_description(Some(group), resource),
                                resource.namespaced,
                            ));
                        }
                    }
                }
            }
        }
        Ok(matched_resources)
    }
}

fn gen_resource_description(
    api_group: Option<&APIGroup>,
    api_resource: &APIResource,
) -> KubeApiResource {
    let gvk = GroupVersionKind {
        group: match api_group {
            Some(group) => group.name.clone(),
            None => String::from(""),
        },
        version: match api_group {
            Some(group) => {
                group
                    .preferred_version
                    .clone()
                    .expect("API Server always has a preferred_version")
                    .version
            }
            None => String::from(""),
        },
        kind: api_resource.kind.clone(),
    };
    KubeApiResource::from_gvk_with_plural(&gvk, &api_resource.name)
}

fn gen_target_identifier(resource: &KubeApiResource, object: &DynamicObject) -> String {
    let meta = object.meta();
    format!(
        "{}/{}/{}/{}",
        resource.group,
        resource.kind,
        meta.namespace.clone().unwrap_or_else(|| "-".to_string()),
        meta.name.clone().expect("Each object has a name")
    )
}

async fn namespaces(k8s_client: Client) -> Result<Vec<String>> {
    let mut namespaces = Vec::new();
    let namespace_api: Api<Namespace> = Api::all(k8s_client);
    let result = namespace_api
        .list(&ListParams::default())
        .await
        .map_err(kube_err)?;
    for namespace in result.iter() {
        if !namespace
            .metadata
            .labels
            .as_ref()
            .map_or(false, |map| map.contains_key("bridgekeeper/ignore"))
        {
            namespaces.push(
                namespace
                    .metadata
                    .name
                    .clone()
                    .expect("Each object has a name"),
            );
        }
    }
    Ok(namespaces)
}

pub async fn run(args: Args) {
    let client = kube::Client::try_default()
        .await
        .expect("Fail early if kube client cannot be created");
    let policies = PolicyStore::new();
    let event_sender = init_event_watcher(&client);
    let mut manager = Manager::new(client.clone(), policies.clone(), event_sender.clone());
    manager
        .load_existing_policies()
        .await
        .expect("Could not load existing policies");
    let auditor = Auditor::new(client, policies);
    match auditor.audit_policies(!args.silent, args.status).await {
        Ok(_) => log::info!("Finished audit"),
        Err(err) => log::error!("Audit failed: {}", err),
    };
}

pub async fn launch_loop(client: kube::Client, policies: PolicyStoreRef, interval: u32) {
    task::spawn(async move {
        let auditor = Auditor::new(client, policies);
        loop {
            sleep(Duration::from_secs(interval as u64)).await;
            log::info!("Starting audit run");
            match auditor.audit_policies(false, true).await {
                Ok(_) => log::info!("Finished audit run"),
                Err(err) => log::error!("Audit run failed: {}", err),
            }
        }
    });
}
