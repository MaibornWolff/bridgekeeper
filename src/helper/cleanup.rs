use crate::constants::*;
use argh::FromArgs;
use k8s_openapi::api::{
    admissionregistration::v1::{MutatingWebhookConfiguration, ValidatingWebhookConfiguration},
    core::v1::Secret,
};
use kube::{api::Api, Client};

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "cleanup")]
/// Delete cert secret and webhook
pub struct Args {
    /// local mode, do not delete secret
    #[argh(switch)]
    local: bool,
}

pub async fn run(args: Args) {
    let client = Client::try_default()
        .await
        .expect("failed to create kube client");
    let namespace = std::env::var("NAMESPACE").unwrap_or_else(|_| "default".into());

    // Delete webhook
    let webhook_api: kube::Api<MutatingWebhookConfiguration> = kube::Api::all(client.clone());
    if let Err(err) = webhook_api
        .delete(ADMISSION_WEBHOOK_NAME, &Default::default())
        .await
    {
        println!("Encountered error when deleting admission webhook: {}", err);
    }
    let webhook_api: kube::Api<ValidatingWebhookConfiguration> = kube::Api::all(client.clone());
    if let Err(err) = webhook_api
        .delete(CONSTRAINT_VALIDATION_WEBHOOK_NAME, &Default::default())
        .await
    {
        println!(
            "Encountered error when deleting constraint validation webhook: {}",
            err
        );
    }

    // Delete secret
    if !args.local {
        let secret_api: Api<Secret> = Api::namespaced(client.clone(), &namespace);
        if let Err(err) = secret_api.delete(SECRET_NAME, &Default::default()).await {
            println!("Encountered error when deleting secret: {}", err);
        }
    }
}
