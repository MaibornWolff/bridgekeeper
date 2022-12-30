use crate::crd::{Policy, PolicySpec};
use crate::util::traits::ObjectStore;
use crate::util::error::{load_err, Result};
use crate::util::types::ObjectReference;
use kube::api::GroupVersionKind;
use kube::core::Resource;
use lazy_static::lazy_static;
use prometheus::{register_gauge, Gauge};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

lazy_static! {
    static ref ACTIVE_POLICIES: Gauge =
        register_gauge!("bridgekeeper_policies_active", "Number of active policies.")
            .expect("creating metric always works");
}

pub struct PolicyStore {
    pub policies: HashMap<String, PolicyInfo>,
}

pub type PolicyStoreRef = Arc<Mutex<PolicyStore>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyInfo {
    pub name: String,
    pub policy: PolicySpec,
    pub ref_info: ObjectReference,
}

impl PolicyStore {
    pub fn new() -> PolicyStoreRef {
        let store = PolicyStore {
            policies: HashMap::new(),
        };
        Arc::new(Mutex::new(store))
    }
}

fn create_object_reference(obj: &Policy) -> ObjectReference {
    ObjectReference {
        api_version: Some(Policy::api_version(&()).to_string()),
        kind: Some(Policy::kind(&()).to_string()),
        name: obj.metadata.name.clone(),
        uid: obj.metadata.uid.clone(),
    }
}

impl PolicyInfo {
    pub fn new(name: String, policy: PolicySpec, ref_info: ObjectReference) -> PolicyInfo {
        PolicyInfo {
            name,
            policy,
            ref_info,
        }
    }

    pub fn is_match(&self, gvk: &GroupVersionKind, namespace: &Option<String>) -> bool {
        for kind in self.policy.target.matches.iter() {
            if (kind.api_group == "*" || kind.api_group.to_lowercase() == gvk.group.to_lowercase())
                && (kind.kind == "*" || kind.kind.to_lowercase() == gvk.kind.to_lowercase())
            {
                if let Some(target_namespace) = namespace {
                    if let Some(namespaces) = &self.policy.target.namespaces {
                        if namespaces.contains(target_namespace) {
                            return true;
                        }
                    } else if let Some(excluded_namespaces) =
                        &self.policy.target.excluded_namespaces
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
        if let Some(namespaces) = &self.policy.target.namespaces {
            namespaces.contains(target_namespace)
        } else if let Some(excluded_namespaces) = &self.policy.target.excluded_namespaces {
            !excluded_namespaces.contains(target_namespace)
        } else {
            true
        }
    }
}

impl ObjectStore<Policy> for PolicyStore {
    fn add_object(&mut self, policy: Policy) -> Option<ObjectReference> {
        let ref_info = create_object_reference(&policy);
        let name = policy.metadata.name.expect("name is always set");
        if let Some(existing_policy_info) = self.policies.get(&name) {
            if existing_policy_info.policy != policy.spec {
                let policy_info = PolicyInfo::new(name.clone(), policy.spec, ref_info.clone());
                log::info!("Policy '{}' updated", name);
                self.policies.insert(name, policy_info);
                Some(ref_info)
            } else {
                None
            }
        } else {
            let policy_info = PolicyInfo::new(name.clone(), policy.spec, ref_info.clone());
            log::info!("Policy '{}' added", name);
            self.policies.insert(name, policy_info);
            ACTIVE_POLICIES.inc();
            Some(ref_info)
        }
    }

    fn remove_object(&mut self, policy: Policy) {
        let name = policy.metadata.name.expect("name is always set");
        log::info!("Policy '{}' removed", name);
        self.policies.remove(&name);
        ACTIVE_POLICIES.dec();
    }
}

pub fn load_policies_from_file(policies: PolicyStoreRef, filename: &str) -> Result<usize> {
    let mut policies = policies.lock().expect("Lock failed");
    let data = std::fs::read_to_string(filename).map_err(load_err)?;

    let mut count = 0;
    for document in serde_yaml::Deserializer::from_str(&data) {
        let policy = Policy::deserialize(document).map_err(load_err)?;
        policies.add_object(policy);
        count += 1;
    }
    Ok(count)
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

        let policy_exact = PolicyInfo::new(
            name.clone(),
            PolicySpec::from_target(target_exact),
            Default::default(),
        );
        let policy_exact_namespace = PolicyInfo::new(
            name.clone(),
            PolicySpec::from_target(target_exact_namespace),
            Default::default(),
        );
        let policy_exact_excluded_namespace = PolicyInfo::new(
            name.clone(),
            PolicySpec::from_target(target_exact_excluded_namespace),
            Default::default(),
        );
        let policy_kind_wildcard = PolicyInfo::new(
            name.clone(),
            PolicySpec::from_target(target_kind_wildcard),
            Default::default(),
        );
        let policy_group_wildcard = PolicyInfo::new(
            name.clone(),
            PolicySpec::from_target(target_group_wildcard),
            Default::default(),
        );
        let policy_all_wildcard = PolicyInfo::new(
            name.clone(),
            PolicySpec::from_target(target_all_wildcard),
            Default::default(),
        );
        let policy_no_match_kind = PolicyInfo::new(
            name.clone(),
            PolicySpec::from_target(target_no_match_kind),
            Default::default(),
        );
        let policy_no_match_group = PolicyInfo::new(
            name.clone(),
            PolicySpec::from_target(target_no_match_group),
            Default::default(),
        );

        assert!(
            policy_exact.is_match(&gvk, &namespace),
            "group and kind should have matched"
        );
        assert!(
            policy_exact_namespace.is_match(&gvk, &namespace),
            "group, kind and namespace should have matched"
        );
        assert!(
            !policy_exact_namespace.is_match(&gvk, &other_namespace),
            "namespace should not have matched"
        );
        assert!(
            policy_exact_excluded_namespace.is_match(&gvk, &other_namespace),
            "group, kind and excluded namespace should have matched"
        );
        assert!(
            !policy_exact_excluded_namespace.is_match(&gvk, &namespace),
            "namespace should not have matched"
        );
        assert!(
            policy_kind_wildcard.is_match(&gvk, &namespace),
            "kind wildcard should have matched"
        );
        assert!(
            policy_group_wildcard.is_match(&gvk, &namespace),
            "group wildcard should have matched"
        );
        assert!(
            policy_all_wildcard.is_match(&gvk, &namespace),
            "complete wildcard should have matched"
        );
        assert!(
            !policy_no_match_kind.is_match(&gvk, &namespace),
            "kind should not have matched"
        );
        assert!(
            !policy_no_match_group.is_match(&gvk, &namespace),
            "group should not have matched"
        );
    }

    #[test]
    fn test_is_namespace_match() {
        let target = Target::from_match(Match::new("example.com", "foobar"));
        let mut policy = PolicyInfo::new(
            "foo".to_string(),
            PolicySpec::from_target(target),
            Default::default(),
        );

        policy.policy.target.namespaces = Some(vec!["foobar".to_string()]);
        policy.policy.target.excluded_namespaces = None;
        assert!(
            policy.is_namespace_match(&"foobar".to_string()),
            "namespace should have matched"
        );

        policy.policy.target.namespaces = None;
        policy.policy.target.excluded_namespaces = Some(vec!["foobar".to_string()]);
        assert!(
            policy.is_namespace_match(&"default".to_string()),
            "namespace should have matched"
        );
        assert!(
            !policy.is_namespace_match(&"foobar".to_string()),
            "namespace should not have matched"
        );

        policy.policy.target.namespaces = Some(vec!["default".to_string()]);
        policy.policy.target.excluded_namespaces = Some(vec!["foobar".to_string()]);
        assert!(
            policy.is_namespace_match(&"default".to_string()),
            "namespace should have matched"
        );
        assert!(
            !policy.is_namespace_match(&"foobar".to_string()),
            "namespace should not have matched"
        );
        assert!(
            !policy.is_namespace_match(&"anythingelse".to_string()),
            "namespace should have matched"
        );
    }
}
