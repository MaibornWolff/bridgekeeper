use rocket::{config::TlsConfig, Config, State};
use rocket_contrib::json::Json;
use std::convert::TryInto;

use crate::util::cert::CertKeyPair;
use crate::watcher::Constraints;
use kube::api::{
    admission::{AdmissionResponse, AdmissionReview},
    DynamicObject,
};

#[rocket::get("/health")]
async fn health() -> &'static str {
    "OK"
}

#[rocket::post("/mutate", data = "<data>")]
async fn admission_mutate(
    data: Json<AdmissionReview<DynamicObject>>,
    constraints: &State<Constraints>,
) -> Json<AdmissionReview<DynamicObject>> {
    let admission_review = data.0;
    let admission_request = admission_review.try_into().unwrap();
    let mut response: AdmissionResponse = AdmissionResponse::from(&admission_request);

    let constraints = constraints.lock().unwrap();

    let (allowed, reason) = constraints.evaluate_constraints(&admission_request);
    response.allowed = allowed;
    if !allowed {
        response.result.message = reason;
        response.result.code = Some(403);
    }

    let review = response.into_review();
    Json(review)
}

pub async fn server(cert: CertKeyPair, watcher: Constraints) {
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
        .manage(watcher)
        .mount("/", rocket::routes![admission_mutate, health])
        .launch()
        .await
        .unwrap();
}
