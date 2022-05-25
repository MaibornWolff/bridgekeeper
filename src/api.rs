use crate::crd::Constraint;
use crate::evaluator::{ConstraintEvaluatorRef, EvaluationResult};
use crate::util::cert::CertKeyPair;
use kube::{
    api::DynamicObject,
    core::admission::{AdmissionResponse, AdmissionReview},
};
use lazy_static::lazy_static;
use prometheus::{register_counter_vec, CounterVec, Encoder, TextEncoder};
use rocket::http::ContentType;
use rocket::{config::TlsConfig, serde::json::Json, Config, State};
use std::convert::TryInto;

lazy_static! {
    static ref HTTP_REQUEST_COUNTER: CounterVec = register_counter_vec!(
        "bridgekeeper_http_requests_total",
        "Number of HTTP requests made.",
        &["path"]
    )
    .unwrap();
}

#[rocket::get("/health")]
async fn health() -> &'static str {
    HTTP_REQUEST_COUNTER.with_label_values(&["/health"]).inc();
    "OK"
}

#[rocket::post("/mutate", data = "<data>")]
async fn admission_mutate(
    data: Json<AdmissionReview<DynamicObject>>,
    evaluator: &State<ConstraintEvaluatorRef>,
) -> Json<AdmissionReview<DynamicObject>> {
    HTTP_REQUEST_COUNTER.with_label_values(&["/mutate"]).inc();
    let admission_review = data.0;
    let admission_request = admission_review.try_into().unwrap();
    let mut response: AdmissionResponse = AdmissionResponse::from(&admission_request);

    let evaluator = evaluator.lock().unwrap();

    let EvaluationResult {
        allowed,
        reason,
        warnings,
        patch,
    } = evaluator.evaluate_constraints(admission_request);
    response.allowed = allowed;
    if !warnings.is_empty() {
        response.warnings = Some(warnings);
    }
    if let Some(patch) = patch {
        response = response.with_patch(patch).unwrap();
    }
    if !allowed {
        response.result.message = reason;
        response.result.code = Some(403);
    }

    let review = response.into_review();
    Json(review)
}

#[rocket::post("/validate_constraint", data = "<data>")]
async fn validate_constraint(
    data: Json<AdmissionReview<Constraint>>,
    evaluator: &State<ConstraintEvaluatorRef>,
) -> Json<AdmissionReview<DynamicObject>> {
    HTTP_REQUEST_COUNTER
        .with_label_values(&["/validate_constraint"])
        .inc();
    let admission_review = data.0;
    let admission_request = admission_review.try_into().unwrap();
    let mut response: AdmissionResponse = AdmissionResponse::from(&admission_request);

    let evaluator = evaluator.lock().unwrap();

    let (allowed, reason) = evaluator.validate_constraint(&admission_request);
    response.allowed = allowed;
    if !allowed {
        response.result.message = reason;
        response.result.code = Some(403);
    }

    let review = response.into_review();
    Json(review)
}

#[rocket::get("/metrics")]
async fn metrics() -> (ContentType, String) {
    HTTP_REQUEST_COUNTER.with_label_values(&["/metrics"]).inc();
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    let body = String::from_utf8(buffer).unwrap();
    (
        ContentType::parse_flexible(encoder.format_type()).unwrap(),
        body,
    )
}

pub async fn server(cert: CertKeyPair, evaluator: ConstraintEvaluatorRef) {
    let config = Config {
        address: "0.0.0.0".parse().unwrap(),
        port: 8081,
        cli_colors: false,
        tls: Some(TlsConfig::from_bytes(
            cert.cert.as_bytes(),
            cert.key.as_bytes(),
        )),
        ..Config::default()
    };

    let _ = rocket::custom(&config)
        .manage(evaluator)
        .mount(
            "/",
            rocket::routes![admission_mutate, validate_constraint, health, metrics],
        )
        .launch()
        .await
        .unwrap();
}
