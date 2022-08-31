use crate::util::webhook::*;
use crate::{constants::*, util::cert::CertKeyPair};
use argh::FromArgs;
use k8s_openapi::api::core::v1::{Namespace, Secret};
use k8s_openapi::ByteString;
use kube::{
    api::{Api, ObjectMeta, Patch, PatchParams},
    Client,
};
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
    /// overwrite existing objects and regenerate certificates
    #[argh(switch)]
    overwrite: bool,
}

pub async fn run(args: Args) {
    let client = Client::try_default()
        .await
        .expect("failed to create kube client");
    let namespace = std::env::var("NAMESPACE").unwrap_or_else(|_| "default".into());

    // Create and store certificate
    let cert = if args.overwrite {
        generate_and_store_certificates(&namespace, &args, &client).await
    } else if let Some(cert) = retrieve_certificates(&namespace, &args, &client).await {
        cert
    } else {
        generate_and_store_certificates(&namespace, &args, &client).await
    };

    // Create webhook
    create_webhooks(&cert, &args, &client).await;

    // Patch namespaces
    patch_namespaces(args, &client).await;
}

async fn retrieve_certificates(
    namespace: &str,
    args: &Args,
    client: &Client,
) -> Option<CertKeyPair> {
    if args.local.is_some() {
        let cert = match std::fs::read_to_string(Path::new(LOCAL_CERTS_DIR).join(CERT_FILENAME)) {
            Ok(data) => data,
            Err(_) => return None,
        };
        let key = match std::fs::read_to_string(Path::new(LOCAL_CERTS_DIR).join(KEY_FILENAME)) {
            Ok(data) => data,
            Err(_) => return None,
        };
        Some(CertKeyPair { cert, key })
    } else {
        let secret_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
        match secret_api.get(SECRET_NAME).await {
            Ok(secret) => match secret.data {
                Some(data) => CertKeyPair::from_secret(&data),
                None => None,
            },
            Err(_) => None,
        }
    }
}

async fn generate_and_store_certificates(
    namespace: &String,
    args: &Args,
    client: &Client,
) -> CertKeyPair {
    let cert = crate::util::cert::gen_cert(SERVICE_NAME.to_string(), namespace, args.local.clone());
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
        let secret_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
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

async fn create_webhooks(cert: &CertKeyPair, args: &Args, client: &Client) {
    create_policy_validation_webhook(client, cert, &args.local, args.strict_admission)
        .await
        .expect("Failed to create policy validation webhook");
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
