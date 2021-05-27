use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use kube::{
    api::{admission::AdmissionRequest, Api, DynamicObject, GroupVersionKind, ListParams},
    Client,
};
use kube_runtime::{watcher, watcher::Event};
use pyo3::prelude::*;

use crate::crd::{Constraint, ConstraintSpec};

pub struct ConstraintList {
    constraints: HashMap<String, ActiveConstraint>,
}

pub type Constraints = Arc<Mutex<ConstraintList>>;

pub struct Watcher {
    k8s_client: Client,
    constraints: Constraints,
}

impl Watcher {
    pub fn new(client: Client) -> Watcher {
        let constraints = Arc::new(Mutex::new(ConstraintList {
            constraints: HashMap::new(),
        }));
        Watcher {
            k8s_client: client,
            constraints,
        }
    }

    pub fn get_constraints(&self) -> Constraints {
        self.constraints.clone()
    }

    pub async fn init(&mut self) {
        let constraints_api = self.constraints_api();
        let res = constraints_api.list(&ListParams::default()).await.unwrap();
        {
            let mut constraints = self.constraints.lock().unwrap();
            for constraint in res {
                constraints.add_constraint(constraint);
            }
        }
    }

    pub async fn start(&mut self) {
        let constraints_api = self.constraints_api();
        let watcher = watcher(constraints_api, ListParams::default());
        let mut pinned_watcher = Box::pin(watcher);
        loop {
            let res = pinned_watcher.next().await;
            match res {
                Some(event) => match event {
                    Ok(event) => {
                        self.handle_event(event);
                    }
                    _ => (),
                },
                _ => (),
            };
        }
    }

    fn constraints_api(&mut self) -> Api<Constraint> {
        Api::all(self.k8s_client.clone())
    }

    fn handle_event(&mut self, event: Event<Constraint>) {
        match event {
            Event::Applied(constraint) => {
                let mut constraints = self.constraints.lock().unwrap();
                constraints.add_constraint(constraint);
            }
            Event::Deleted(constraint) => {
                let mut constraints = self.constraints.lock().unwrap();
                constraints.remove_constraint(constraint);
            }
            _ => (),
        }
    }
}

impl ConstraintList {
    pub fn add_constraint(&mut self, constraint: Constraint) {
        let name = constraint.metadata.name.unwrap();
        log::info!("Constraint '{}' added", name);
        let constraint_watcher = ActiveConstraint::new(name.clone(), constraint.spec);
        self.constraints.insert(name, constraint_watcher);
    }

    pub fn remove_constraint(&mut self, constraint: Constraint) {
        let name = constraint.metadata.name.unwrap();
        log::info!("Constraint '{}' removed", name);
        self.constraints.remove(&name);
    }

    pub fn evaluate_constraints(
        &self,
        request: &AdmissionRequest<DynamicObject>,
    ) -> (bool, Option<String>) {
        let namespace = request.namespace.clone();
        let gvk = &request.kind;
        for value in self.constraints.values() {
            if value.is_match(&gvk, &namespace) {
                log::info!(
                    "Resource {}/{}.{}/{} matches in constraint {}",
                    namespace.clone().unwrap_or("-".to_string()),
                    gvk.kind,
                    gvk.group,
                    request.name,
                    value.name
                );
                let res = value.evaluate_constraint(request);
                if res.0 {
                    log::info!("Constraint '{}' evaluates to {}", value.name, res.0);
                } else {
                    log::info!(
                        "Constraint '{}' evaluates to {} with message '{}'",
                        value.name,
                        res.0,
                        res.1.as_ref().unwrap()
                    );
                    // If one constraint fails no need to evaluate the others
                    return res;
                }
            }
        }
        log::debug!(
            "No constraint found for request: {} of {}/{} in namespace '{:?}'",
            request.name,
            gvk.group,
            gvk.kind,
            namespace
        );
        (true, None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActiveConstraint {
    name: String,
    constraint: ConstraintSpec,
}

impl ActiveConstraint {
    pub fn new(name: String, constraint: ConstraintSpec) -> ActiveConstraint {
        ActiveConstraint { name, constraint }
    }

    pub fn is_match(&self, gvk: &GroupVersionKind, namespace: &Option<String>) -> bool {
        for kind in self.constraint.target.matches.iter() {
            if (kind.api_group == "*" || kind.api_group.to_lowercase() == gvk.group.to_lowercase())
                && (kind.kind == "*" || kind.kind.to_lowercase() == gvk.kind.to_lowercase())
            {
                if let Some(target_namespace) = namespace {
                    if let Some(namespaces) = &self.constraint.target.namespaces {
                        if namespaces.contains(target_namespace) {
                            return true;
                        }
                    } else if let Some(excluded_namespaces) =
                        &self.constraint.target.excluded_namespaces
                    {
                        if !excluded_namespaces.contains(target_namespace) {
                            return true;
                        }
                    } else {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
        false
    }

    pub fn evaluate_constraint(
        &self,
        request: &AdmissionRequest<DynamicObject>,
    ) -> (bool, Option<String>) {
        Python::with_gil(|py| {
            let obj = pythonize::pythonize(py, &request).unwrap();
            if let Ok(rule_code) =
                PyModule::from_code(py, &self.constraint.rule.python, "rule.py", "bridgekeeper")
            {
                if let Ok(result) = rule_code.call1("validate", (obj,)) {
                    let extracted_result: Result<(bool, String), PyErr> = result.extract();
                    match extracted_result {
                        Ok(result) => (result.0, Some(result.1)),
                        Err(_) => match result.extract() {
                            Ok(result) => (result, None),
                            Err(_) => (
                                false,
                                Some(
                                    "Validation function did not return expected return types"
                                        .to_string(),
                                ),
                            ),
                        },
                    }
                } else {
                    (false, Some("Validation function failed".to_string()))
                }
            } else {
                (
                    false,
                    Some("Validation function could not be compiled".to_string()),
                )
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{Match, Target};

    #[test]
    fn test_is_match() {
        let name = "foo".to_string();
        let namespace = Some("default".to_string());
        let other_namespace = Some("someothernamespace".to_string());
        let gvk = GroupVersionKind::gvk("example.com", "v1", "foobar");

        let target_exact = Target::from_match(Match::new("example.com", "foobar"));
        let target_kind_wildcard = Target::from_match(Match::new("example.com", "*"));
        let target_group_wildcard = Target::from_match(Match::new("*", "foobar"));
        let target_all_wildcard = Target::from_match(Match::new("*", "*"));
        let target_no_match_kind = Target::from_match(Match::new("example.com", "baz"));
        let target_no_match_group = Target::from_match(Match::new("complex.com", "foobar"));

        let mut target_exact_namespace = Target::from_match(Match::new("example.com", "foobar"));
        target_exact_namespace.namespaces = Some(vec!["default".to_string()]);
        let mut target_exact_excluded_namespace =
            Target::from_match(Match::new("example.com", "foobar"));
        target_exact_excluded_namespace.excluded_namespaces = Some(vec!["default".to_string()]);

        let constraint_exact =
            ActiveConstraint::new(name.clone(), ConstraintSpec::from_target(target_exact));
        let constraint_exact_namespace = ActiveConstraint::new(
            name.clone(),
            ConstraintSpec::from_target(target_exact_namespace),
        );
        let constraint_exact_excluded_namespace = ActiveConstraint::new(
            name.clone(),
            ConstraintSpec::from_target(target_exact_excluded_namespace),
        );
        let constraint_kind_wildcard = ActiveConstraint::new(
            name.clone(),
            ConstraintSpec::from_target(target_kind_wildcard),
        );
        let constraint_group_wildcard = ActiveConstraint::new(
            name.clone(),
            ConstraintSpec::from_target(target_group_wildcard),
        );
        let constraint_all_wildcard = ActiveConstraint::new(
            name.clone(),
            ConstraintSpec::from_target(target_all_wildcard),
        );
        let constraint_no_match_kind = ActiveConstraint::new(
            name.clone(),
            ConstraintSpec::from_target(target_no_match_kind),
        );
        let constraint_no_match_group = ActiveConstraint::new(
            name.clone(),
            ConstraintSpec::from_target(target_no_match_group),
        );

        assert!(
            constraint_exact.is_match(&gvk, &namespace),
            "group and kind should have matched"
        );
        assert!(
            constraint_exact_namespace.is_match(&gvk, &namespace),
            "group, kind and namespace should have matched"
        );
        assert!(
            !constraint_exact_namespace.is_match(&gvk, &other_namespace),
            "namespace should not have matched"
        );
        assert!(
            constraint_exact_excluded_namespace.is_match(&gvk, &other_namespace),
            "group, kind and excluded namespace should have matched"
        );
        assert!(
            !constraint_exact_excluded_namespace.is_match(&gvk, &namespace),
            "namespace should not have matched"
        );
        assert!(
            constraint_kind_wildcard.is_match(&gvk, &namespace),
            "kind wildcard should have matched"
        );
        assert!(
            constraint_group_wildcard.is_match(&gvk, &namespace),
            "group wildcard should have matched"
        );
        assert!(
            constraint_all_wildcard.is_match(&gvk, &namespace),
            "complete wildcard should have matched"
        );
        assert!(
            !constraint_no_match_kind.is_match(&gvk, &namespace),
            "kind should not have matched"
        );
        assert!(
            !constraint_no_match_group.is_match(&gvk, &namespace),
            "group should not have matched"
        );
    }
}
