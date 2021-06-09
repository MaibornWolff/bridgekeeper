use crate::{constants::*, util::cert::CertKeyPair};
use argh::FromArgs;
use k8s_openapi::api::{
    admissionregistration::v1::{MutatingWebhookConfiguration, ValidatingWebhookConfiguration},
    core::v1::{Namespace, Secret},
};
use k8s_openapi::ByteString;
use kube::{
    api::Api,
    api::PatchParams,
    api::{ObjectMeta, Patch},
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
}

#[derive(rust_embed::RustEmbed)]
#[folder = "manifests/"]
struct Assets;

pub async fn run(args: Args) {
    let client = Client::try_default().await.unwrap();
    let namespace = std::env::var("NAMESPACE").unwrap_or("default".into());

    // Create and store certificate
    let cert =
        crate::util::cert::gen_cert(SERVICE_NAME.to_string(), &namespace, args.local.clone());
    if args.local.is_some() {
        let _ = create_dir(LOCAL_CERTS_DIR);
        let mut cert_file = File::create(Path::new(LOCAL_CERTS_DIR).join(CERT_FILENAME)).unwrap();
        cert_file.write_all(cert.cert.as_bytes()).unwrap();
        let mut key_file = File::create(Path::new(LOCAL_CERTS_DIR).join(KEY_FILENAME)).unwrap();
        key_file.write_all(cert.key.as_bytes()).unwrap();
    } else {
        let secret_api: Api<Secret> = Api::namespaced(client.clone(), &namespace);
        let mut metadata = ObjectMeta::default();
        metadata.namespace = Some(namespace.clone());
        metadata.name = Some(SECRET_NAME.to_string());
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
        if let Ok(_) = secret_api.get(&SECRET_NAME).await {
            secret_api
                .delete(&SECRET_NAME, &Default::default())
                .await
                .unwrap();
        }
        secret_api
            .create(&Default::default(), &secret)
            .await
            .unwrap();
    }

    // Create webhook
    let webhook_data = if args.local.is_some() {
        Assets::get("admission-controller-local.yaml")
    } else {
        Assets::get("admission-controller.yaml")
    }
    .unwrap();
    let webhook_data = String::from_utf8(webhook_data.to_vec()).unwrap();
    apply_webhook::<MutatingWebhookConfiguration>(
        &client,
        webhook_data,
        &cert,
        &namespace,
        &args.local,
    )
    .await;

    let webhook_data = if args.local.is_some() {
        Assets::get("constraint-validation-controller-local.yaml")
    } else {
        Assets::get("constraint-validation-controller.yaml")
    }
    .unwrap();
    let webhook_data = String::from_utf8(webhook_data.to_vec()).unwrap();
    apply_webhook::<ValidatingWebhookConfiguration>(
        &client,
        webhook_data,
        &cert,
        &namespace,
        &args.local,
    )
    .await;

    // Patch namespaces
    let namespace_api: Api<Namespace> = Api::all(client.clone());
    for namespace in args.ignore_namespace {
        if let Ok(_) = namespace_api.get(&namespace).await {
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
                .unwrap();
        }
    }
}

async fn apply_webhook<T: Resource>(
    client: &kube::Client,
    webhook_data: String,
    cert: &CertKeyPair,
    namespace: &String,
    local: &Option<String>,
) where
    <T as Resource>::DynamicType: Default,
    T: Clone,
    T: Serialize,
    T: DeserializeOwned,
    T: std::fmt::Debug,
{
    let mut webhook_data = webhook_data
        .replace("<cadata>", &base64::encode(cert.cert.clone()))
        .replace("<namespace>", &namespace);
    if let Some(local_name) = local {
        webhook_data =
            webhook_data.replace("<host>", &local_name.to_lowercase().replace("ip:", ""));
    }
    let webhook_data = serde_yaml::from_str(&webhook_data).unwrap();

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
