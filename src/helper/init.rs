use crate::{constants::*, util::cert::CertKeyPair};
use argh::FromArgs;
use k8s_openapi::api::{
    admissionregistration::v1::{MutatingWebhookConfiguration, ValidatingWebhookConfiguration},
    core::v1::{Namespace, Secret},
};
use k8s_openapi::ByteString;
use kube::{
    api::{Api, ObjectMeta, Patch, PatchParams},
    Client, Resource,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use std::io::prelude::*;
use std::{
    collections::BTreeMap,
    fs::{create_dir, File},
    path::Path,
};

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "init")]
/// create server cert secret and webhook
pub struct Args {
    /// run in local mode, value is target for the webhook, e.g. host.k3d.internal:8081, if you use an ip specify as IP:192.168.1.1:8081
    #[argh(option)]
    local: Option<String>,
    /// patch namespace to ignore it for validation
    #[argh(option)]
    ignore_namespace: Vec<String>,
    /// whether or not to fail admission requests when bridgekeeper fails or is not reachable
    #[argh(switch)]
    strict_admission: bool,
}

#[derive(rust_embed::RustEmbed)]
#[folder = "manifests/"]
struct Assets;

pub async fn run(args: Args) {
    let client = Client::try_default()
        .await
        .expect("failed to create kube client");
    let namespace = std::env::var("NAMESPACE").unwrap_or_else(|_| "default".into());

    // Create and store certificate
    let cert = generate_and_store_certificates(&namespace, &args, &client).await;

    // Create webhook
    create_webhooks(&namespace, &cert, &args, &client).await;

    // Patch namespaces
    patch_namespaces(args, &client).await;
}

async fn generate_and_store_certificates(
    namespace: &String,
    args: &Args,
    client: &Client,
) -> CertKeyPair {
    let cert =
        crate::util::cert::gen_cert(SERVICE_NAME.to_string(), &namespace, args.local.clone());
    if args.local.is_some() {
        let _ = create_dir(LOCAL_CERTS_DIR);
        let mut cert_file = File::create(Path::new(LOCAL_CERTS_DIR).join(CERT_FILENAME))
            .expect("failed to create cert file");
        cert_file
            .write_all(cert.cert.as_bytes())
            .expect("failed to write cert");
        let mut key_file = File::create(Path::new(LOCAL_CERTS_DIR).join(KEY_FILENAME))
            .expect("failed to create key file");
        key_file
            .write_all(cert.key.as_bytes())
            .expect("failed to write key");
    } else {
        let secret_api: Api<Secret> = Api::namespaced(client.clone(), &namespace);
        let metadata = ObjectMeta {
            name: Some(SECRET_NAME.to_string()),
            namespace: Some(namespace.clone()),
            ..Default::default()
        };
        let mut data: BTreeMap<String, ByteString> = std::collections::BTreeMap::new();
        data.insert(
            CACERT_FILENAME.to_string(),
            ByteString(cert.cert.as_bytes().to_vec()),
        );
        data.insert(
            CERT_FILENAME.to_string(),
            ByteString(cert.cert.as_bytes().to_vec()),
        );
        data.insert(
            KEY_FILENAME.to_string(),
            ByteString(cert.key.as_bytes().to_vec()),
        );
        let secret = Secret {
            data: Some(data),
            immutable: None,
            metadata,
            string_data: None,
            type_: None,
        };
        if secret_api.get(SECRET_NAME).await.is_ok() {
            secret_api
                .delete(SECRET_NAME, &Default::default())
                .await
                .expect("failed to delete existing certificate secret");
        }
        secret_api
            .create(&Default::default(), &secret)
            .await
            .expect("failed to create certificate secret");
    }
    cert
}

async fn create_webhooks(namespace: &str, cert: &CertKeyPair, args: &Args, client: &Client) {
    let failure_policy = if args.strict_admission {
        "Fail"
    } else {
        "Ignore"
    };
    let webhook_data = if args.local.is_some() {
        Assets::get("admission-controller-local.yaml")
    } else {
        Assets::get("admission-controller.yaml")
    }
    .expect("failed to read admission controller template");
    let webhook_data = String::from_utf8(webhook_data.data.to_vec())
        .expect("failed to parse admission controller template");
    apply_webhook::<MutatingWebhookConfiguration>(
        &client,
        webhook_data,
        &cert,
        namespace,
        &args.local,
        failure_policy,
    )
    .await;

    let webhook_data = if args.local.is_some() {
        Assets::get("constraint-validation-controller-local.yaml")
    } else {
        Assets::get("constraint-validation-controller.yaml")
    }
    .expect("failed to read contraint admission controller template");
    let webhook_data = String::from_utf8(webhook_data.data.to_vec())
        .expect("failed to parse constraint admission controller template");
    apply_webhook::<ValidatingWebhookConfiguration>(
        &client,
        webhook_data,
        &cert,
        namespace,
        &args.local,
        failure_policy,
    )
    .await;
}

async fn patch_namespaces(args: Args, client: &Client) {
    let namespace_api: Api<Namespace> = Api::all(client.clone());
    for namespace in args.ignore_namespace {
        if namespace_api.get(&namespace).await.is_ok() {
            let patch_params = PatchParams::apply(MANAGER_NAME);
            let patch = Patch::Merge(json!({
                "metadata": {
                    "labels": {
                        "bridgekeeper/ignore": "true"
                    }
                }
            }));
            namespace_api
                .patch(&namespace, &patch_params, &patch)
                .await
                .expect("failed to patch namespace labels");
        }
    }
}

async fn apply_webhook<T: Resource>(
    client: &kube::Client,
    webhook_data: String,
    cert: &CertKeyPair,
    namespace: &str,
    local: &Option<String>,
    failure_policy: &str,
) where
    <T as Resource>::DynamicType: Default,
    T: Clone,
    T: Serialize,
    T: DeserializeOwned,
    T: std::fmt::Debug,
{
    let mut webhook_data = webhook_data
        .replace("<cadata>", &base64::encode(cert.cert.clone()))
        .replace("<namespace>", namespace)
        .replace("<failure_policy>", failure_policy);
    if let Some(local_name) = local {
        webhook_data =
            webhook_data.replace("<host>", &local_name.to_lowercase().replace("ip:", ""));
    }
    let webhook_data = serde_yaml::from_str(&webhook_data).expect("failed to read webhook data");

    let webhook_api: kube::Api<T> = kube::Api::all(client.clone());
    if let Ok(_res) = webhook_api.get(WEBHOOK_NAME).await {
        println!("Webhook already exists. Deleting old resource");
        match webhook_api.delete(WEBHOOK_NAME, &Default::default()).await {
            Ok(_res) => (),
            Err(err) => println!("{:?}", err),
        };
    }
    match webhook_api.create(&Default::default(), &webhook_data).await {
        Ok(_res) => (),
        Err(err) => println!("{:?}", err),
    };
}
