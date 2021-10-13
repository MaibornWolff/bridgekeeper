use crate::crd::{Constraint, ConstraintSpec};
use k8s_openapi::api::core::v1::ObjectReference as KubeObjectReference;
use kube::api::GroupVersionKind;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use prometheus::register_gauge;
use prometheus::Gauge;

lazy_static! {
    static ref ACTIVE_CONSTRAINTS: Gauge = register_gauge!(
        "bridgekeeper_constraints_active",
        "Number of active constraints."
    )
    .unwrap();
}

pub struct ConstraintStore {
    pub constraints: HashMap<String, ConstraintInfo>,
}

pub type ConstraintStoreRef = Arc<Mutex<ConstraintStore>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConstraintInfo {
    pub name: String,
    pub constraint: ConstraintSpec,
    pub ref_info: ConstraintObjectReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConstraintObjectReference {
    pub api_version: Option<String>,
    pub kind: Option<String>,
    pub name: Option<String>,
    pub uid: Option<String>,
}

impl Default for ConstraintObjectReference {
    fn default() -> Self {
        Self {
            api_version: None,
            kind: None,
            name: None,
            uid: None,
        }
    }
}

impl ConstraintObjectReference {
    pub fn to_object_reference(&self) -> KubeObjectReference {
        let mut object_reference = KubeObjectReference::default();
        object_reference.api_version = self.api_version.clone();
        object_reference.kind = self.kind.clone();
        object_reference.name = self.name.clone();
        object_reference.uid = self.uid.clone();
        object_reference
    }
}

impl ConstraintStore {
    pub fn new() -> ConstraintStoreRef {
        let store = ConstraintStore {
            constraints: HashMap::new(),
        };
        Arc::new(Mutex::new(store))
    }
}

fn create_object_reference(obj: &Constraint) -> ConstraintObjectReference {
    ConstraintObjectReference {
        api_version: Some(obj.api_version.clone()),
        kind: Some(obj.kind.clone()),
        name: obj.metadata.name.clone(),
        uid: obj.metadata.uid.clone(),
    }
}

impl ConstraintInfo {
    pub fn new(
        name: String,
        constraint: ConstraintSpec,
        ref_info: ConstraintObjectReference,
    ) -> ConstraintInfo {
        ConstraintInfo {
            name,
            constraint,
            ref_info,
        }
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

    pub fn is_namespace_match(&self, target_namespace: &String) -> bool {
        if let Some(namespaces) = &self.constraint.target.namespaces {
            return namespaces.contains(target_namespace);
        } else if let Some(excluded_namespaces) = &self.constraint.target.excluded_namespaces {
            return !excluded_namespaces.contains(target_namespace);
        } else {
            return true;
        }
    }
}

impl ConstraintStore {
    pub fn add_constraint(&mut self, constraint: Constraint) -> Option<ConstraintObjectReference> {
        let ref_info = create_object_reference(&constraint);
        let name = constraint.metadata.name.unwrap();
        if let Some(existing_constraint_info) = self.constraints.get(&name) {
            if existing_constraint_info.constraint != constraint.spec {
                let constraint_info =
                    ConstraintInfo::new(name.clone(), constraint.spec, ref_info.clone());
                log::info!("Constraint '{}' updated", name);
                self.constraints.insert(name, constraint_info);
                Some(ref_info)
            } else {
                None
            }
        } else {
            let constraint_info =
                ConstraintInfo::new(name.clone(), constraint.spec, ref_info.clone());
            log::info!("Constraint '{}' added", name);
            self.constraints.insert(name, constraint_info);
            ACTIVE_CONSTRAINTS.inc();
            Some(ref_info)
        }
    }

    pub fn remove_constraint(&mut self, constraint: Constraint) {
        let name = constraint.metadata.name.unwrap();
        log::info!("Constraint '{}' removed", name);
        self.constraints.remove(&name);
        ACTIVE_CONSTRAINTS.dec();
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

        let constraint_exact = ConstraintInfo::new(
            name.clone(),
            ConstraintSpec::from_target(target_exact),
            Default::default(),
        );
        let constraint_exact_namespace = ConstraintInfo::new(
            name.clone(),
            ConstraintSpec::from_target(target_exact_namespace),
            Default::default(),
        );
        let constraint_exact_excluded_namespace = ConstraintInfo::new(
            name.clone(),
            ConstraintSpec::from_target(target_exact_excluded_namespace),
            Default::default(),
        );
        let constraint_kind_wildcard = ConstraintInfo::new(
            name.clone(),
            ConstraintSpec::from_target(target_kind_wildcard),
            Default::default(),
        );
        let constraint_group_wildcard = ConstraintInfo::new(
            name.clone(),
            ConstraintSpec::from_target(target_group_wildcard),
            Default::default(),
        );
        let constraint_all_wildcard = ConstraintInfo::new(
            name.clone(),
            ConstraintSpec::from_target(target_all_wildcard),
            Default::default(),
        );
        let constraint_no_match_kind = ConstraintInfo::new(
            name.clone(),
            ConstraintSpec::from_target(target_no_match_kind),
            Default::default(),
        );
        let constraint_no_match_group = ConstraintInfo::new(
            name.clone(),
            ConstraintSpec::from_target(target_no_match_group),
            Default::default(),
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

    #[test]
    fn test_is_namespace_match() {
        let target = Target::from_match(Match::new("example.com", "foobar"));
        let mut constraint = ConstraintInfo::new(
            "foo".to_string(),
            ConstraintSpec::from_target(target),
            Default::default(),
        );

        constraint.constraint.target.namespaces = Some(vec!["foobar".to_string()]);
        constraint.constraint.target.excluded_namespaces = None;
        assert!(
            constraint.is_namespace_match(&"foobar".to_string()),
            "namespace should have matched"
        );

        constraint.constraint.target.namespaces = None;
        constraint.constraint.target.excluded_namespaces = Some(vec!["foobar".to_string()]);
        assert!(
            constraint.is_namespace_match(&"default".to_string()),
            "namespace should have matched"
        );
        assert!(
            !constraint.is_namespace_match(&"foobar".to_string()),
            "namespace should not have matched"
        );

        constraint.constraint.target.namespaces = Some(vec!["default".to_string()]);
        constraint.constraint.target.excluded_namespaces = Some(vec!["foobar".to_string()]);
        assert!(
            constraint.is_namespace_match(&"default".to_string()),
            "namespace should have matched"
        );
        assert!(
            !constraint.is_namespace_match(&"foobar".to_string()),
            "namespace should not have matched"
        );
        assert!(
            !constraint.is_namespace_match(&"anythingelse".to_string()),
            "namespace should have matched"
        );
    }
}
