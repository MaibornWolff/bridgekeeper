use crate::util::error::{kube_err, Result};
use crate::{constants::*, util::cert::CertKeyPair, util::k8s_client::apply};
use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
};
use kube::{Client, Resource};
use serde::{de::DeserializeOwned, Serialize};

#[derive(rust_embed::RustEmbed)]
#[folder = "manifests/"]
struct Assets;

pub async fn create_admission_webhook(
    client: &Client,
    cert: &CertKeyPair,
    local: &Option<String>,
    strict_admission: bool,
    timeout_seconds: Option<u8>
) -> Result<()> {
    let webhook_data = if local.is_some() {
        Assets::get("admission-controller-local.yaml")
    } else {
        Assets::get("admission-controller.yaml")
    }
    .expect("failed to read admission controller template");
    let webhook_data = String::from_utf8(webhook_data.data.to_vec())
        .expect("failed to parse admission controller template");

    match apply_webhook::<MutatingWebhookConfiguration>(
        client,
        ADMISSION_WEBHOOK_NAME,
        webhook_data,
        cert,
        local,
        strict_admission,
        timeout_seconds.unwrap_or(5)
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(err) => Err(kube_err(err)),
    }
}

pub async fn create_policy_validation_webhook(
    client: &Client,
    cert: &CertKeyPair,
    local: &Option<String>,
    strict_admission: bool,
) -> Result<()> {
    let webhook_data = if local.is_some() {
        Assets::get("policy-validation-controller-local.yaml")
    } else {
        Assets::get("policy-validation-controller.yaml")
    }
    .expect("failed to read admission controller template");
    let webhook_data = String::from_utf8(webhook_data.data.to_vec())
        .expect("failed to parse admission controller template");

    match apply_webhook::<ValidatingWebhookConfiguration>(
        client,
        POLICY_VALIDATION_WEBHOOK_NAME,
        webhook_data,
        cert,
        local,
        strict_admission,
        5
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(err) => Err(kube_err(err)),
    }
}

async fn apply_webhook<T: Resource>(
    client: &kube::Client,
    name: &str,
    webhook_data: String,
    cert: &CertKeyPair,
    local: &Option<String>,
    strict_admission: bool,
    mut timeout_seconds: u8,
) -> kube::Result<T>
where
    <T as Resource>::DynamicType: Default,
    T: Clone,
    T: Serialize,
    T: DeserializeOwned,
    T: std::fmt::Debug,
{
    if timeout_seconds > 30 {
        timeout_seconds = 30;
    }
    let failure_policy = if strict_admission { "Fail" } else { "Ignore" };
    let namespace = std::env::var("NAMESPACE").unwrap_or_else(|_| "default".into());
    let mut webhook_data = webhook_data
        .replace("<cadata>", &base64::encode(cert.cert.clone()))
        .replace("<namespace>", &namespace)
        .replace("<failure_policy>", failure_policy)
        .replace("<timeout_seconds>", timeout_seconds.to_string().as_str());
    if let Some(local_name) = local {
        webhook_data =
            webhook_data.replace("<host>", &local_name.to_lowercase().replace("ip:", ""));
    }
    let webhook_data: T = serde_yaml::from_str(&webhook_data).expect("failed to read webhook data");

    let webhook_api: kube::Api<T> = kube::Api::all(client.clone());

    apply(&webhook_api, name, webhook_data).await
}
