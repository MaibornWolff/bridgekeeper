use crate::constants::POD_CERTS_DIR;
use crate::evaluator::PolicyEvaluator;
use crate::events::init_event_watcher;
use crate::manager::Manager;
use crate::policy::PolicyStore;
use argh::FromArgs;

#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "server")]
/// run server with admission webhook endpoint
pub struct Args {
    /// path to the directory containing tls.crt and tls.key
    #[argh(option, short = 'c')]
    cert_dir: Option<String>,
    /// enable/disable audit feature
    #[argh(switch)]
    audit: bool,
    /// audit interval in seconds, by default 600s ( = 10 minutes)
    #[argh(option)]
    audit_interval: Option<u32>,
    /// whether or not to fail admission requests when bridgekeeper fails or is not reachable
    #[argh(switch)]
    strict_admission: bool,
    /// timeout in seconds for admission requests, defaults to 5 seconds, maximum 30 seconds
    #[argh(option)]
    admission_timeout_seconds: Option<u8>,
    /// run in local mode, value is target for the webhook, e.g. host.k3d.internal:8081, if you use an ip specify as IP:192.168.1.1:8081
    #[argh(option)]
    local: Option<String>,
}

pub async fn run(args: Args) {
    let client = kube::Client::try_default()
        .await
        .expect("failed to create kube client");
    // Read certs
    let cert_dir = args.cert_dir.unwrap_or_else(|| POD_CERTS_DIR.to_string());
    let cert = crate::util::cert::wait_for_certs(cert_dir);

    // Create admission webhook, ignore error as that likely means another intstance already updated the hook
    let _ = crate::util::webhook::create_admission_webhook(
        &client,
        &cert,
        &args.local,
        args.strict_admission,
        args.admission_timeout_seconds,
    )
    .await;

    // Initiate services
    let policies = PolicyStore::new();
    let event_sender = init_event_watcher(&client);
    let mut manager = Manager::new(client.clone(), policies.clone(), event_sender.clone());
    let evaluator = PolicyEvaluator::new(policies.clone(), event_sender.clone());
    manager.start().await;
    manager
        .load_existing_policies()
        .await
        .expect("Could not load existing policies");

    if args.audit {
        crate::audit::launch_loop(client, policies, args.audit_interval.unwrap_or(600)).await;
    }

    // Launch API with webhook endpoint
    crate::api::server(cert, evaluator).await;
}
