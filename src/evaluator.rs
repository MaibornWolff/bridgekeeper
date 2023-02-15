use crate::{
    crd::{Policy, PolicySpec},
    events::{EventSender, PolicyEvent, PolicyEventData},
    policy::{PolicyInfo, PolicyStoreRef},
    util::k8s::find_k8s_resource_matches,
};
use kube::{
    core::{
        admission::{self, Operation},
        DynamicObject,
    },
    Client,
};
use lazy_static::lazy_static;
use prometheus::{register_counter_vec, CounterVec};
use pyo3::prelude::*;
use serde_derive::Serialize;
use std::sync::Arc;
use tracing::{info, warn};

lazy_static! {
    static ref MATCHED_POLICIES: CounterVec = register_counter_vec!(
        "bridgekeeper_policy_matched",
        "Number of admissions matched to a policy.",
        &["name"]
    )
    .expect("creating metric always works");
    static ref POLICY_EVALUATIONS_SUCCESS: CounterVec = register_counter_vec!(
        "bridgekeeper_policy_evaluated_success",
        "Number of successfull policy evaluations",
        &["name"]
    )
    .expect("creating metric always works");
    static ref POLICY_EVALUATIONS_REJECT: CounterVec = register_counter_vec!(
        "bridgekeeper_policy_evaluated_reject",
        "Number of failed policy evaluations.",
        &["name"]
    )
    .expect("creating metric always works");
    static ref POLICY_EVALUATIONS_ERROR: CounterVec = register_counter_vec!(
        "bridgekeeper_policy_evaluated_error",
        "Number of policy evaluations that had an error.",
        &["name"]
    )
    .expect("creating metric always works");
    static ref POLICY_VALIDATIONS_FAIL: CounterVec = register_counter_vec!(
        "bridgekeeper_policy_validation_fail",
        "Number of policy validations that failed.",
        &["name"]
    )
    .expect("creating metric always works");
}

#[derive(Serialize)]
pub struct ValidationRequest {
    pub object: DynamicObject,
    pub operation: Operation,
}

impl ValidationRequest {
    pub fn from(
        admission_request: admission::AdmissionRequest<DynamicObject>,
    ) -> Option<ValidationRequest> {
        if let Some(object) = admission_request.object {
            Some(ValidationRequest {
                object,
                operation: admission_request.operation,
            })
        } else {
            None
        }
    }
}

pub struct PolicyEvaluator {
    policies: PolicyStoreRef,
    event_sender: EventSender,
}

pub struct EvaluationResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub warnings: Vec<String>,
    pub patch: Option<json_patch::Patch>,
}

pub type PolicyEvaluatorRef = Arc<PolicyEvaluator>;

impl PolicyEvaluator {
    pub fn new(policies: PolicyStoreRef, event_sender: EventSender) -> PolicyEvaluatorRef {
        let evaluator = PolicyEvaluator {
            policies,
            event_sender,
        };
        pyo3::prepare_freethreaded_python();
        Arc::new(evaluator)
    }

    pub fn evaluate_policies(
        &self,
        admission_request: admission::AdmissionRequest<DynamicObject>,
    ) -> EvaluationResult {
        let mut warnings = Vec::new();
        let namespace = admission_request.namespace.clone();
        let name = admission_request.name.clone();
        let gvk = admission_request.kind.clone();
        let request = match ValidationRequest::from(admission_request) {
            Some(request) => request,
            None => {
                return EvaluationResult {
                    allowed: true,
                    reason: Some("no object in request".to_string()),
                    warnings: vec![],
                    patch: None,
                }
            }
        };
        let policies = self.policies.lock().expect("lock failed. Cannot continue");

        let mut matching_policies = Vec::new();

        // Collect all matching policies
        for value in policies.policies.values() {
            if value.is_match(&gvk, &namespace) {
                MATCHED_POLICIES
                    .with_label_values(&[value.name.as_str()])
                    .inc();
                info!(
                    "Object {}.{}/{}/{} matches policy {}",
                    gvk.kind,
                    gvk.group,
                    namespace.clone().unwrap_or_else(|| "-".to_string()),
                    name,
                    value.name
                );
                matching_policies.push(value.clone());
            }
        }
        // Release the lock
        drop(policies);

        // Evaluate policies
        let mut patches: Option<json_patch::Patch> = None;
        for value in matching_policies.iter() {
            let target_identifier = format!(
                "{}/{}/{}/{}",
                gvk.group,
                gvk.kind,
                namespace.clone().unwrap_or_else(|| "-".to_string()),
                name
            );
            let res = evaluate_policy(value, &request);
            if let Some(mut patch) = res.2 {
                if let Some(patches) = patches.as_mut() {
                    patches.0.append(&mut patch.0);
                } else {
                    patches = Some(patch);
                }
            }
            self.event_sender
                .send(PolicyEvent {
                    policy_reference: value.ref_info.clone(),
                    event_data: PolicyEventData::Evaluated {
                        target_identifier,
                        result: res.0,
                        reason: res.1.clone(),
                    },
                })
                .unwrap_or_else(|err| warn!("Could not send event: {:?}", err));
            if res.0 {
                POLICY_EVALUATIONS_SUCCESS
                    .with_label_values(&[value.name.as_str()])
                    .inc();
                info!("Policy '{}' evaluates to {}", value.name, res.0);
                if let Some(warning) = res.1 {
                    warnings.push(warning);
                }
            } else {
                POLICY_EVALUATIONS_REJECT
                    .with_label_values(&[value.name.as_str()])
                    .inc();
                let reason = res.1.unwrap_or_else(|| "-".to_string());
                info!(
                    "Policy '{}' evaluates to {} with message '{}'",
                    value.name, res.0, reason,
                );
                if value.policy.enforce.unwrap_or(true) {
                    // If one policy fails no need to evaluate the others
                    return EvaluationResult {
                        allowed: res.0,
                        reason: Some(reason),
                        warnings,
                        patch: None,
                    };
                } else {
                    warnings.push(reason);
                }
            }
        }
        EvaluationResult {
            allowed: true,
            reason: None,
            warnings,
            patch: patches,
        }
    }
}

pub async fn validate_policy_admission(
    request: &admission::AdmissionRequest<Policy>,
) -> (bool, Option<String>) {
    if let Some(policy) = request.object.as_ref() {
        let name = match policy.metadata.name.as_ref() {
            Some(name) => name.as_str(),
            None => "-invalidname-",
        };
        validate_policy(name, &policy.spec).await
    } else {
        (false, Some("No rule found".to_string()))
    }
}

pub async fn validate_policy(name: &str, policy: &PolicySpec) -> (bool, Option<String>) {
    let client = Client::try_default()
        .await
        .expect("failed to create kube client");

    // Iterate through match items and check whether specified resources exist in the cluster
    for match_item in policy.target.matches.iter() {
        let api_resource_exists =
            match find_k8s_resource_matches(&match_item.api_group, &match_item.kind, &client).await
            {
                Ok(resources) => !resources.is_empty(),
                Err(_) => false,
            };

        if !api_resource_exists {
            return (
                false,
                Some(format!(
                    "Specified target {}/{} is not available",
                    match_item.api_group, match_item.kind
                )),
            );
        }
    }

    let python_code = policy.rule.python.clone();
    Python::with_gil(|py| {
        if let Err(err) = PyModule::from_code(py, &python_code, "rule.py", "bridgekeeper") {
            POLICY_VALIDATIONS_FAIL.with_label_values(&[name]).inc();
            (false, Some(format!("Python compile error: {:?}", err)))
        } else {
            (true, None)
        }
    })
}

fn evaluate_policy(
    policy: &PolicyInfo,
    request: &ValidationRequest,
) -> (bool, Option<String>, Option<json_patch::Patch>) {
    let name = &policy.name;
    Python::with_gil(|py| {
        let obj = match pythonize::pythonize(py, &request) {
            Ok(obj) => obj,
            Err(err) => return fail(name, &format!("Failed to initialize python: {}", err)),
        };

        match PyModule::from_code(py, &policy.policy.rule.python, "rule.py", "bridgekeeper") {
            Ok(rule_code) => {
                if let Ok(validation_function) = rule_code.getattr("validate") {
                    match validation_function.call1((obj,)) {
                        Ok(result) => extract_result(name, request, result),
                        Err(err) => fail(name, &format!("Validation function failed: {}", err)),
                    }
                } else {
                    fail(name, "Validation function not found in code")
                }
            }
            Err(err) => fail(
                name,
                format!("Validation function could not be compiled: {}", err).as_str(),
            ),
        }
    })
}

pub fn evaluate_policy_audit(
    policy: &PolicyInfo,
    object: DynamicObject,
) -> (bool, Option<String>, Option<json_patch::Patch>) {
    let request = ValidationRequest {
        object,
        operation: Operation::Update,
    };
    evaluate_policy(policy, &request)
}

fn extract_result(
    name: &str,
    request: &ValidationRequest,
    result: &PyAny,
) -> (bool, Option<String>, Option<json_patch::Patch>) {
    if let Ok((code, reason, patched)) = result.extract::<(bool, Option<String>, &PyAny)>() {
        if let Ok(result) = pythonize::depythonize::<serde_json::Value>(patched) {
            match generate_patches(&request.object, &result) {
                Ok(patch) => (code, reason, Some(patch)),
                Err(error) => fail(name, &format!("failed to compute patch: {}", error)),
            }
        } else {
            fail(
                name,
                "Could not read patched object returned by validation function",
            )
        }
    } else if let Ok((code, reason)) = result.extract::<(bool, Option<String>)>() {
        (code, reason, None)
    } else if let Ok(code) = result.extract::<bool>() {
        (code, None, None)
    } else {
        fail(name, "Validation function did not return expected types")
    }
}

fn fail(name: &str, reason: &str) -> (bool, Option<String>, Option<json_patch::Patch>) {
    POLICY_EVALUATIONS_ERROR.with_label_values(&[name]).inc();
    (false, Some(reason.to_string()), None)
}

fn generate_patches(
    input: &DynamicObject,
    patched: &serde_json::Value,
) -> Result<json_patch::Patch, String> {
    let input = match serde_json::to_value(input) {
        Ok(input) => input,
        Err(error) => return Err(error.to_string()),
    };
    Ok(json_patch::diff(&input, patched))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::PolicySpec;
    use kube::core::ObjectMeta;

    #[test]
    fn test_simple_evaluate() {
        pyo3::prepare_freethreaded_python();
        let python = r#"
def validate(request):
    return True
        "#;
        let policy_spec = PolicySpec::from_python(python.to_string());
        let policy = PolicyInfo::new("test".to_string(), policy_spec, Default::default());

        let object = DynamicObject {
            types: None,
            metadata: ObjectMeta::default(),
            data: serde_json::Value::Null,
        };
        let request = ValidationRequest {
            object,
            operation: Operation::Create,
        };

        let (res, reason, patch) = evaluate_policy(&policy, &request);
        assert!(res, "validate function failed: {}", reason.unwrap());
        assert!(reason.is_none());
        assert!(patch.is_none());
    }

    #[test]
    fn test_simple_evaluate_with_reason() {
        pyo3::prepare_freethreaded_python();
        let python = r#"
def validate(request):
    return False, "foobar"
        "#;
        let policy_spec = PolicySpec::from_python(python.to_string());
        let policy = PolicyInfo::new("test".to_string(), policy_spec, Default::default());

        let object = DynamicObject {
            types: None,
            metadata: ObjectMeta::default(),
            data: serde_json::Value::Null,
        };
        let request = ValidationRequest {
            object,
            operation: Operation::Create,
        };

        let (res, reason, patch) = evaluate_policy(&policy, &request);
        assert!(!res);
        assert!(reason.is_some());
        assert_eq!("foobar".to_string(), reason.unwrap());
        assert!(patch.is_none());
    }

    #[test]
    fn test_evaluate_with_invalid_python() {
        pyo3::prepare_freethreaded_python();
        let python = r#"
def validate(request):
    return false, "foobar"
        "#;
        let policy_spec = PolicySpec::from_python(python.to_string());
        let policy = PolicyInfo::new("test".to_string(), policy_spec, Default::default());

        let object = DynamicObject {
            types: None,
            metadata: ObjectMeta::default(),
            data: serde_json::Value::Null,
        };
        let request = ValidationRequest {
            object,
            operation: Operation::Create,
        };

        let (res, reason, patch) = evaluate_policy(&policy, &request);
        assert!(!res);
        assert!(reason.is_some());
        assert_eq!(
            "Validation function failed: NameError: name 'false' is not defined".to_string(),
            reason.unwrap()
        );
        assert!(patch.is_none());
    }

    #[test]
    fn test_simple_mutate() {
        pyo3::prepare_freethreaded_python();
        let python = r#"
def validate(request):
    object = request["object"]
    object["b"] = "2"
    return True, None, object
        "#;
        let policy_spec = PolicySpec::from_python(python.to_string());
        let policy = PolicyInfo::new("test".to_string(), policy_spec, Default::default());

        let data = serde_json::from_str(r#"{"a": 1, "b": "1"}"#).unwrap();
        let object = DynamicObject {
            types: None,
            metadata: ObjectMeta::default(),
            data,
        };
        let request = ValidationRequest {
            object,
            operation: Operation::Create,
        };

        let (res, reason, patch) = evaluate_policy(&policy, &request);
        assert!(res, "validate function failed: {}", reason.unwrap());
        assert!(reason.is_none());
        assert!(patch.is_some());
        let patch = patch.unwrap();
        assert_eq!(1, patch.0.len());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                r#"[{"op": "replace", "path": "/b", "value": "2"}]"#
            )
            .unwrap(),
            serde_json::to_value(patch.0).unwrap()
        );
    }
}
