use crate::crd::Policy;
use crate::evaluator::{validate_policy_admission, EvaluationResult, PolicyEvaluatorRef};
use crate::util::cert::CertKeyPair;
use kube::{
    api::DynamicObject,
    core::admission::{AdmissionResponse, AdmissionReview},
};
use lazy_static::lazy_static;
use prometheus::{register_counter_vec, CounterVec, Encoder, TextEncoder};
use rocket::http::ContentType;
use rocket::log::LogLevel;
use rocket::response::Responder;
use rocket::{config::TlsConfig, serde::json::Json, Config, State};
use std::convert::TryInto;

lazy_static! {
    static ref HTTP_REQUEST_COUNTER: CounterVec = register_counter_vec!(
        "bridgekeeper_http_requests_total",
        "Number of HTTP requests made.",
        &["path"]
    )
    .expect("creating metric always works");
}

#[derive(Responder)]
enum ApiError {
    #[response(status = 400)]
    InvalidRequest(String),
    #[response(status = 500)]
    ProcessingFailure(String),
}

#[rocket::get("/health")]
async fn health() -> &'static str {
    HTTP_REQUEST_COUNTER.with_label_values(&["/health"]).inc();
    "OK"
}

#[rocket::post("/mutate", data = "<data>")]
async fn admission_mutate(
    data: Json<AdmissionReview<DynamicObject>>,
    evaluator: &State<PolicyEvaluatorRef>,
) -> Result<Json<AdmissionReview<DynamicObject>>, ApiError> {
    HTTP_REQUEST_COUNTER.with_label_values(&["/mutate"]).inc();
    let admission_review = data.0;
    let admission_request = admission_review.try_into().map_err(|err| {
        ApiError::InvalidRequest(format!("Failed to parse admissionrequest: {}", err))
    })?;
    let mut response: AdmissionResponse = AdmissionResponse::from(&admission_request);

    let evaluator = evaluator.inner().clone();
    let EvaluationResult {
        allowed,
        reason,
        warnings,
        patch,
    } = tokio::task::spawn_blocking(move || evaluator.evaluate_policies(admission_request))
        .await
        .map_err(|err| {
            ApiError::ProcessingFailure(format!("Error evaluating policies: {}", err))
        })?;

    response.allowed = allowed;
    if !warnings.is_empty() {
        response.warnings = Some(warnings);
    }
    if let Some(patch) = patch {
        response = response.with_patch(patch).map_err(|err| {
            ApiError::ProcessingFailure(format!(
                "Failed to serialize patch from validation function: {}",
                err
            ))
        })?;
    }
    if !allowed {
        response.result.message = reason.unwrap_or_default();
        response.result.code = 403;
    }

    let review = response.into_review();
    Ok(Json(review))
}

#[rocket::post("/validate-policy", data = "<data>")]
async fn api_validate_policy(
    data: Json<AdmissionReview<Policy>>,
) -> Result<Json<AdmissionReview<DynamicObject>>, ApiError> {
    HTTP_REQUEST_COUNTER
        .with_label_values(&["/validate-policy"])
        .inc();
    let admission_review = data.0;
    let admission_request = admission_review.try_into().map_err(|err| {
        ApiError::InvalidRequest(format!("Failed to parse admissionrequest: {}", err))
    })?;
    let mut response: AdmissionResponse = AdmissionResponse::from(&admission_request);

    let (allowed, reason) = validate_policy_admission(&admission_request).await;
    response.allowed = allowed;
    if !allowed {
        response.result.message = reason.unwrap_or_default();
        response.result.code = 403;
    }

    let review = response.into_review();
    Ok(Json(review))
}

#[rocket::get("/metrics")]
async fn metrics() -> Result<(ContentType, String), ApiError> {
    HTTP_REQUEST_COUNTER.with_label_values(&["/metrics"]).inc();
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|err| ApiError::InvalidRequest(format!("Failed to encode metrics: {}", err)))?;
    let body = String::from_utf8(buffer)
        .map_err(|err| ApiError::InvalidRequest(format!("Failed to encode metrics: {}", err)))?;
    Ok((
        match ContentType::parse_flexible(encoder.format_type()) {
            Some(content_type) => content_type,
            None => {
                return Err(ApiError::ProcessingFailure(
                    "Failed to parse content type".to_string(),
                ))
            }
        },
        body,
    ))
}

pub async fn server(cert: CertKeyPair, evaluator: PolicyEvaluatorRef) {
    let config = Config {
        address: "0.0.0.0".parse().unwrap(),
        port: 8081,
        cli_colors: false,
        tls: Some(TlsConfig::from_bytes(
            cert.cert.as_bytes(),
            cert.key.as_bytes(),
        )),
        log_level: LogLevel::Off,
        ..Config::default()
    };

    let _ = rocket::custom(&config)
        .manage(evaluator)
        .mount(
            "/",
            rocket::routes![admission_mutate, api_validate_policy, health, metrics],
        )
        .launch()
        .await
        .expect("failed to launch rocket server");
}
