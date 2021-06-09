use crate::{
    constraint::{ConstraintInfo, ConstraintStoreRef},
    crd::Constraint,
    events::{ConstraintEvent, ConstraintEventData, EventSender},
};
use kube::api::{admission::AdmissionRequest, DynamicObject};
use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

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
        Arc::new(Mutex::new(evaluator))
    }

    pub fn evaluate_constraints(
        &self,
        request: &AdmissionRequest<DynamicObject>,
    ) -> (bool, Option<String>) {
        let namespace = request.namespace.clone();
        let gvk = &request.kind;
        if let Ok(constraints) = self.constraints.lock() {
            for value in constraints.constraints.values() {
                if value.is_match(&gvk, &namespace) {
                    log::info!(
                        "Resource {}/{}.{}/{} matches in constraint {}",
                        namespace.clone().unwrap_or("-".to_string()),
                        gvk.kind,
                        gvk.group,
                        request.name,
                        value.name
                    );
                    let target_identifier = format!(
                        "{}/{}/{}/{}",
                        gvk.group,
                        gvk.kind,
                        namespace.clone().unwrap_or("-".to_string()),
                        request.name
                    );
                    let res = evaluate_constraint(&value, request);
                    self.event_sender
                        .send(ConstraintEvent {
                            constraint_reference: value.ref_info.clone(),
                            event_data: ConstraintEventData::EVALUATED {
                                target_identifier,
                                result: res.0,
                                reason: res.1.clone(),
                            },
                        })
                        .unwrap_or_else(|err| log::warn!("Could not send event: {:?}", err));
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
        } else {
            panic!("Should not happen");
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
    Python::with_gil(|py| {
        let obj = pythonize::pythonize(py, &request).unwrap();
        if let Ok(rule_code) = PyModule::from_code(
            py,
            &constraint.constraint.rule.python,
            "rule.py",
            "bridgekeeper",
        ) {
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
