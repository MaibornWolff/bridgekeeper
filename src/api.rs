use crate::crd::Policy;
use crate::evaluator::{
    validate_policy_admission, EvaluationResult, PolicyEvaluatorRef, PolicyValidationResult,
};
use crate::util::cert::CertKeyPair;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper::{header, HeaderMap, StatusCode};
use kube::{
    api::DynamicObject,
    core::admission::{AdmissionResponse, AdmissionReview},
};
use lazy_static::lazy_static;
use prometheus::{register_counter_vec, CounterVec, Encoder, TextEncoder};
use simple_hyper_server_tls::{hyper_from_pem_data, Protocols};
use std::convert::TryInto;
use std::sync::Arc;
use tracing::warn;

lazy_static! {
    static ref HTTP_REQUEST_COUNTER: CounterVec = register_counter_vec!(
        "bridgekeeper_http_requests_total",
        "Number of HTTP requests made.",
        &["path"]
    )
    .expect("creating metric always works");
}

enum ApiError {
    InvalidRequest(String),
    ProcessingFailure(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            ApiError::ProcessingFailure(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
        }
    }
}

struct AppState {
    pub evaluator: PolicyEvaluatorRef,
}

async fn health() -> &'static str {
    HTTP_REQUEST_COUNTER.with_label_values(&["/health"]).inc();
    "OK"
}

async fn admission_mutate(
    State(state): State<Arc<AppState>>,
    Json(admission_review): Json<AdmissionReview<DynamicObject>>,
) -> Result<Json<AdmissionReview<DynamicObject>>, ApiError> {
    HTTP_REQUEST_COUNTER.with_label_values(&["/mutate"]).inc();
    let admission_request = admission_review.try_into().map_err(|err| {
        ApiError::InvalidRequest(format!("Failed to parse admissionrequest: {}", err))
    })?;
    let mut response: AdmissionResponse = AdmissionResponse::from(&admission_request);

    let evaluator = state.evaluator.clone();
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

async fn api_validate_policy(
    Json(admission_review): Json<AdmissionReview<Policy>>,
) -> Result<Json<AdmissionReview<DynamicObject>>, ApiError> {
    HTTP_REQUEST_COUNTER
        .with_label_values(&["/validate-policy"])
        .inc();
    let admission_request = admission_review.try_into().map_err(|err| {
        ApiError::InvalidRequest(format!("Failed to parse admissionrequest: {}", err))
    })?;
    let mut response: AdmissionResponse = AdmissionResponse::from(&admission_request);

    match validate_policy_admission(&admission_request).await {
        PolicyValidationResult::Valid => {
            response.allowed = true;
        }
        PolicyValidationResult::Invalid { reason } => {
            response.allowed = false;
            response.result.message = reason;
            response.result.code = 403;
        }
    };

    let review = response.into_review();
    Ok(Json(review))
}

async fn metrics() -> Result<impl IntoResponse, ApiError> {
    HTTP_REQUEST_COUNTER.with_label_values(&["/metrics"]).inc();
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|err| ApiError::InvalidRequest(format!("Failed to encode metrics: {}", err)))?;
    let body = String::from_utf8(buffer)
        .map_err(|err| ApiError::InvalidRequest(format!("Failed to encode metrics: {}", err)))?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/openmetrics-text; version=1.0.0; charset=utf-8"
            .parse()
            .unwrap(),
    );
    Ok((headers, body))
}

pub async fn server(cert: CertKeyPair, evaluator: PolicyEvaluatorRef) {
    let state = AppState { evaluator };
    let app = Router::new()
        .route("/mutate", post(admission_mutate))
        .route("/validate-policy", post(api_validate_policy))
        .route("/metrics", get(metrics))
        .route("/health", get(health))
        .with_state(Arc::new(state));

    let server = hyper_from_pem_data(
        cert.cert.as_bytes(),
        cert.key.as_bytes(),
        Protocols::HTTP1,
        &"0.0.0.0:8081".parse().unwrap(),
    )
    .unwrap();

    let mut server = server.serve(app.into_make_service());

    while let Err(e) = (&mut server).await {
        warn!("HTTP server error: {}", e);
    }
}
