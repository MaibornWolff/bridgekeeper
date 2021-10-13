use crate::constraint::{ConstraintInfo, ConstraintStore, ConstraintStoreRef};
use crate::crd::{Constraint, ConstraintStatus, Violation};
use crate::events::init_event_watcher;
use crate::manager::Manager;
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
        register_counter!("bridgekeeper_audit_runs", "Number of audit runs.").unwrap();
    static ref NUM_CHECKED_OBJECTS: Gauge = register_gauge!(
        "bridgekeeper_audit_checked_objects",
        "Number of objects checked in last audit run."
    )
    .unwrap();
    static ref NUM_VIOLATIONS: Gauge = register_gauge!(
        "bridgekeeper_audit_violations",
        "Number of violations in last audit run."
    )
    .unwrap();
    static ref NUM_CHECKED_CONSTRAINTS: Gauge = register_gauge!(
        "bridgekeeper_audit_constraints",
        "Number of constraints checked in last audit run."
    )
    .unwrap();
    static ref TIMESTAMP_LAST_RUN: Gauge = register_gauge!(
        "bridgekeeper_audit_last_run_timestamp_seconds",
        "Time in seconds since unix epoch when audit was last run."
    )
    .unwrap();
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "audit")]
/// Audit existing constraints
pub struct Args {
    /// update constraint status with list of violations
    #[argh(switch)]
    status: bool,
    /// do not print violations
    #[argh(switch, short = 's')]
    silent: bool,
}

pub struct Auditor {
    k8s_client: Client,
    constraints: ConstraintStoreRef,
    //event_sender: EventSender,
}

impl Auditor {
    pub fn new(
        client: Client,
        constraints: ConstraintStoreRef,
        //event_sender: EventSender,
    ) -> Auditor {
        pyo3::prepare_freethreaded_python();
        Auditor {
            k8s_client: client,
            constraints,
            //event_sender,
        }
    }

    pub async fn audit_constraints(&self, print_violations: bool, update_status: bool) {
        let mut constraints = Vec::new();
        // While holding the lock only collect the constraints, directly auditing them would make the future of the method not implement Send which breaks the task spawn
        {
            let constraint_store = self.constraints.lock().unwrap();
            for constraint in constraint_store.constraints.values() {
                if constraint.constraint.audit.unwrap_or(false) {
                    constraints.push(constraint.clone());
                }
            }
        }
        let mut num_objects = 0;
        let mut num_violations = 0;
        for constraint in constraints.iter() {
            let (processed_objects, processed_violations) = self
                .audit_constraint(constraint, print_violations, update_status)
                .await;
            num_objects += processed_objects;
            num_violations += processed_violations;
        }
        let now: DateTime<Utc> = SystemTime::now().into();
        NUM_CHECKED_CONSTRAINTS.set(constraints.len() as f64);
        NUM_CHECKED_OBJECTS.set(num_objects as f64);
        NUM_VIOLATIONS.set(num_violations as f64);
        NUM_AUDIT_RUNS.inc();
        TIMESTAMP_LAST_RUN.set(now.timestamp() as f64);
    }

    pub async fn audit_constraint(
        &self,
        constraint: &ConstraintInfo,
        print_violations: bool,
        update_status: bool,
    ) -> (usize, usize) {
        // collect all matching k8s resources
        let namespaces = namespaces(self.k8s_client.clone()).await;
        let mut matched_resources: Vec<(KubeApiResource, bool)> = Vec::new();
        for target_match in constraint.constraint.target.matches.iter() {
            let mut result = self
                .find_k8s_resource_matches(&target_match.api_group, &target_match.kind)
                .await;
            matched_resources.append(&mut result);
        }

        // audit all objects
        let mut results = Vec::new();
        let mut num_objects = 0;

        for (resource_description, namespaced) in matched_resources.iter() {
            if *namespaced {
                for namespace in namespaces.iter() {
                    if constraint.is_namespace_match(namespace) {
                        let api = Api::<DynamicObject>::namespaced_with(
                            self.k8s_client.clone(),
                            namespace,
                            &resource_description,
                        );
                        let objects = api.list(&ListParams::default()).await.unwrap();
                        for object in objects {
                            num_objects += 1;
                            let target_identifier =
                                gen_target_identifier(resource_description, &object);
                            let (result, message) =
                                crate::evaluator::evaluate_constraint_audit(constraint, object);
                            if !result {
                                results.push((target_identifier, message));
                            }
                        }
                    }
                }
            } else {
                let api =
                    Api::<DynamicObject>::all_with(self.k8s_client.clone(), &resource_description);
                let objects = api.list(&ListParams::default()).await.unwrap();
                for object in objects {
                    let target_identifier = gen_target_identifier(resource_description, &object);
                    let (result, message) =
                        crate::evaluator::evaluate_constraint_audit(constraint, object);
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
                    None => format!(""),
                };
                println!(
                    "{} violates constraint '{}'{}",
                    object, constraint.name, message
                );
            }
        }
        let num_violations = results.len();
        // Attach audit results to constraint status
        if update_status {
            self.report_result(constraint.name.clone(), results).await;
        }
        (num_objects, num_violations)
    }

    async fn report_result(&self, name: String, results: Vec<(String, Option<String>)>) {
        let api: Api<Constraint> = Api::all(self.k8s_client.clone());
        let mut status = ConstraintStatus::new();
        let mut audit_status = status.audit.as_mut().unwrap();
        let now: DateTime<Utc> = SystemTime::now().into();
        audit_status.timestamp = Some(now.to_rfc3339());

        let mut violations = Vec::new();
        for result in results {
            let violation = Violation {
                identifier: result.0,
                message: result.1.unwrap_or(String::from("N/A")),
            };
            violations.push(violation);
        }
        audit_status.violations = Some(violations);

        let crd_resource = Constraint::api_resource();
        let new_status = Patch::Merge(json!({
            "apiVersion": crd_resource.api_version,
            "kind": crd_resource.kind,
            "status": status,
        }));
        let ps = PatchParams::default();
        api.patch_status(&name, &ps, &new_status).await.unwrap();
    }

    async fn find_k8s_resource_matches(
        &self,
        api_group: &String,
        kind: &String,
    ) -> Vec<(KubeApiResource, bool)> {
        let mut matched_resources = Vec::new();
        // core api group
        if api_group == "" {
            let versions = self.k8s_client.list_core_api_versions().await.unwrap();
            let version = versions.versions.first().unwrap();
            let resources = self
                .k8s_client
                .list_core_api_resources(version)
                .await
                .unwrap();
            for resource in resources.resources.iter() {
                if (kind == "*" || resource.kind.to_lowercase() == kind.to_lowercase())
                    && !resource.name.contains("/")
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
                .unwrap()
                .groups
                .iter()
            {
                if api_group == "*" || group.name.to_lowercase() == api_group.to_lowercase() {
                    let api_version = group.preferred_version.clone().unwrap().group_version;
                    for resource in self
                        .k8s_client
                        .list_api_group_resources(&api_version)
                        .await
                        .unwrap()
                        .resources
                        .iter()
                    {
                        if (kind == "*" || resource.kind.to_lowercase() == kind.to_lowercase())
                            && !resource.name.contains("/")
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
        matched_resources
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
            Some(group) => group.preferred_version.clone().unwrap().version,
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
        meta.namespace.clone().unwrap_or("-".to_string()),
        meta.name.clone().unwrap()
    )
}

async fn namespaces(k8s_client: Client) -> Vec<String> {
    let mut namespaces = Vec::new();
    let namespace_api: Api<Namespace> = Api::all(k8s_client);
    let result = namespace_api.list(&ListParams::default()).await.unwrap();
    for namespace in result.iter() {
        if !namespace
            .metadata
            .labels
            .contains_key("bridgekeeper/ignore")
        {
            namespaces.push(namespace.metadata.name.clone().unwrap());
        }
    }
    namespaces
}

pub async fn run(args: Args) {
    let client = kube::Client::try_default().await.unwrap();
    let constraints = ConstraintStore::new();
    let event_sender = init_event_watcher(&client);
    let mut manager = Manager::new(client.clone(), constraints.clone(), event_sender.clone());
    manager.load_existing_constraints().await;
    let auditor = Auditor::new(client, constraints);
    auditor.audit_constraints(!args.silent, args.status).await;
}

pub async fn launch_loop(client: kube::Client, constraints: ConstraintStoreRef, interval: u32) {
    task::spawn(async move {
        let auditor = Auditor::new(client, constraints);
        loop {
            sleep(Duration::from_secs(interval as u64)).await;
            log::info!("Starting audit run");
            auditor.audit_constraints(false, true).await;
            log::info!("Finished audit run");
        }
    });
}
