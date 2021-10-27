use crate::{
    constraint::{ConstraintInfo, ConstraintStoreRef},
    crd::Constraint,
    events::{ConstraintEvent, ConstraintEventData, EventSender},
};
use kube::core::{admission::AdmissionRequest, DynamicObject};
use lazy_static::lazy_static;
use prometheus::{register_counter_vec, CounterVec};
use pyo3::prelude::*;
use serde_derive::Serialize;
use std::sync::{Arc, Mutex};

lazy_static! {
    static ref MATCHED_CONSTRAINTS: CounterVec = register_counter_vec!(
        "bridgekeeper_constraint_matched",
        "Number of admissions matched to a constraint.",
        &["name"]
    )
    .unwrap();
    static ref CONSTRAINT_EVALUATIONS_SUCCESS: CounterVec = register_counter_vec!(
        "bridgekeeper_constraint_evaluated_success",
        "Number of successfull constraint evaluations",
        &["name"]
    )
    .unwrap();
    static ref CONSTRAINT_EVALUATIONS_REJECT: CounterVec = register_counter_vec!(
        "bridgekeeper_constraint_evaluated_reject",
        "Number of failed constraint evaluations.",
        &["name"]
    )
    .unwrap();
    static ref CONSTRAINT_EVALUATIONS_ERROR: CounterVec = register_counter_vec!(
        "bridgekeeper_constraint_evaluated_error",
        "Number of constraint evaluations that had an error.",
        &["name"]
    )
    .unwrap();
    static ref CONSTRAINT_VALIDATIONS_FAIL: CounterVec = register_counter_vec!(
        "bridgekeeper_constraint_validation_fail",
        "Number of constraint validations that failed.",
        &["name"]
    )
    .unwrap();
}

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DummyOperation {
    Audit,
}

#[derive(Serialize)]
pub struct AuditRequest {
    pub object: DynamicObject,
    pub operation: DummyOperation,
}

pub struct ConstraintEvaluator {
    constraints: ConstraintStoreRef,
    event_sender: EventSender,
}

pub type ConstraintEvaluatorRef = Arc<Mutex<ConstraintEvaluator>>;

impl ConstraintEvaluator {
    pub fn new(
        constraints: ConstraintStoreRef,
        event_sender: EventSender,
    ) -> ConstraintEvaluatorRef {
        let evaluator = ConstraintEvaluator {
            constraints,
            event_sender,
        };
        pyo3::prepare_freethreaded_python();
        Arc::new(Mutex::new(evaluator))
    }

    pub fn evaluate_constraints(
        &self,
        request: &AdmissionRequest<DynamicObject>,
    ) -> (bool, Option<String>, Vec<String>) {
        let mut warnings = Vec::new();
        let namespace = request.namespace.clone();
        let gvk = &request.kind;
        if let Ok(constraints) = self.constraints.lock() {
            for value in constraints.constraints.values() {
                if value.is_match(gvk, &namespace) {
                    MATCHED_CONSTRAINTS
                        .with_label_values(&[value.name.as_str()])
                        .inc();
                    log::info!(
                        "Object {}.{}/{}/{} matches constraint {}",
                        gvk.kind,
                        gvk.group,
                        namespace.clone().unwrap_or_else(|| "-".to_string()),
                        request.name,
                        value.name
                    );
                    let target_identifier = format!(
                        "{}/{}/{}/{}",
                        gvk.group,
                        gvk.kind,
                        namespace.clone().unwrap_or_else(|| "-".to_string()),
                        request.name
                    );
                    let res = evaluate_constraint(value, request);
                    self.event_sender
                        .send(ConstraintEvent {
                            constraint_reference: value.ref_info.clone(),
                            event_data: ConstraintEventData::Evaluated {
                                target_identifier,
                                result: res.0,
                                reason: res.1.clone(),
                            },
                        })
                        .unwrap_or_else(|err| log::warn!("Could not send event: {:?}", err));
                    if res.0 {
                        CONSTRAINT_EVALUATIONS_SUCCESS
                            .with_label_values(&[value.name.as_str()])
                            .inc();
                        log::info!("Constraint '{}' evaluates to {}", value.name, res.0);
                        if res.1.is_some() {
                            warnings.push(res.1.unwrap());
                        }
                    } else {
                        CONSTRAINT_EVALUATIONS_REJECT
                            .with_label_values(&[value.name.as_str()])
                            .inc();
                        log::info!(
                            "Constraint '{}' evaluates to {} with message '{}'",
                            value.name,
                            res.0,
                            res.1.as_ref().unwrap()
                        );
                        if value.constraint.enforce.unwrap_or(true) {
                            // If one constraint fails no need to evaluate the others
                            return (res.0, res.1, warnings);
                        } else {
                            warnings.push(res.1.unwrap());
                        }
                    }
                }
            }
            (true, None, warnings)
        } else {
            panic!("Could not lock constraints mutex");
        }
    }

    pub fn validate_constraint(
        &self,
        request: &AdmissionRequest<Constraint>,
    ) -> (bool, Option<String>) {
        if let Some(constraint) = request.object.as_ref() {
            let python_code = constraint.spec.rule.python.clone();
            Python::with_gil(|py| {
                if let Err(err) = PyModule::from_code(py, &python_code, "rule.py", "bridgekeeper") {
                    CONSTRAINT_VALIDATIONS_FAIL
                        .with_label_values(&[constraint.metadata.name.as_ref().unwrap().as_str()])
                        .inc();
                    (false, Some(format!("Python compile error: {:?}", err)))
                } else {
                    (true, None)
                }
            })
        } else {
            (false, Some("No rule found".to_string()))
        }
    }
}

fn evaluate_constraint(
    constraint: &ConstraintInfo,
    request: &AdmissionRequest<DynamicObject>,
) -> (bool, Option<String>) {
    let name = &constraint.name;
    Python::with_gil(|py| {
        let obj = pythonize::pythonize(py, &request).unwrap();
        if let Ok(rule_code) = PyModule::from_code(
            py,
            &constraint.constraint.rule.python,
            "rule.py",
            "bridgekeeper",
        ) {
            if let Ok(validation_function) = rule_code.getattr("validate") {
                if let Ok(result) = validation_function.call1((obj,)) {
                    let extracted_result: Result<(bool, String), PyErr> = result.extract();
                    match extracted_result {
                        Ok(result) => (result.0, Some(result.1)),
                        Err(_) => match result.extract() {
                            Ok(result) => (result, None),
                            Err(_) => {
                                fail(name, "Validation function did not return expected types")
                            }
                        },
                    }
                } else {
                    fail(name, "Validation function failed")
                }
            } else {
                fail(name, "Validation function not found in code")
            }
        } else {
            fail(name, "Validation function could not be compiled")
        }
    })
}

pub fn evaluate_constraint_audit(
    constraint: &ConstraintInfo,
    object: DynamicObject,
) -> (bool, Option<String>) {
    let name = &constraint.name;
    let request = AuditRequest {
        object,
        operation: DummyOperation::Audit,
    };
    Python::with_gil(|py| {
        let obj = pythonize::pythonize(py, &request).unwrap();
        if let Ok(rule_code) = PyModule::from_code(
            py,
            &constraint.constraint.rule.python,
            "rule.py",
            "bridgekeeper",
        ) {
            if let Ok(validation_function) = rule_code.getattr("validate") {
                if let Ok(result) = validation_function.call1((obj,)) {
                    let extracted_result: Result<(bool, String), PyErr> = result.extract();
                    match extracted_result {
                        Ok(result) => (result.0, Some(result.1)),
                        Err(_) => match result.extract() {
                            Ok(result) => (result, None),
                            Err(_) => {
                                fail(name, "Validation function did not return expected types")
                            }
                        },
                    }
                } else {
                    fail(name, "Validation function failed")
                }
            } else {
                fail(name, "Validation function not found in code")
            }
        } else {
            fail(name, "Validation function could not be compiled")
        }
    })
}

fn fail(name: &str, reason: &str) -> (bool, Option<String>) {
    CONSTRAINT_EVALUATIONS_ERROR
        .with_label_values(&[name])
        .inc();
    (false, Some(reason.to_string()))
}
