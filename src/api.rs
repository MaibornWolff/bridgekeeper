use crate::crd::Constraint;
use crate::evaluator::ConstraintEvaluatorRef;
use crate::util::cert::CertKeyPair;
use kube::api::{
    admission::{AdmissionResponse, AdmissionReview},
    DynamicObject,
};
use rocket::{config::TlsConfig, serde::json::Json, Config, State};
use std::convert::TryInto;

#[rocket::get("/health")]
async fn health() -> &'static str {
    "OK"
}

#[rocket::post("/mutate", data = "<data>")]
async fn admission_mutate(
    data: Json<AdmissionReview<DynamicObject>>,
    evaluator: &State<ConstraintEvaluatorRef>,
) -> Json<AdmissionReview<DynamicObject>> {
    let admission_review = data.0;
    let admission_request = admission_review.try_into().unwrap();
    let mut response: AdmissionResponse = AdmissionResponse::from(&admission_request);

    let evaluator = evaluator.lock().unwrap();

    let (allowed, reason) = evaluator.evaluate_constraints(&admission_request);
    response.allowed = allowed;
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

    rocket::custom(&config)
        .manage(evaluator)
        .mount(
            "/",
            rocket::routes![admission_mutate, validate_constraint, health],
        )
        .launch()
        .await
        .unwrap();
}
