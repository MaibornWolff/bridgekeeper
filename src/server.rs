use argh::FromArgs;

use crate::constants::POD_CERTS_DIR;
use crate::constraint::ConstraintStore;
use crate::evaluator::ConstraintEvaluator;
use crate::events::init_event_watcher;
use crate::manager::Manager;

#[derive(FromArgs, PartialEq, Debug)]
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
}

pub async fn run(args: Args) {
    let client = kube::Client::try_default().await.unwrap();
    // Read certs
    let cert_dir = args.cert_dir.unwrap_or_else(|| POD_CERTS_DIR.to_string());
    let cert = crate::util::cert::wait_for_certs(cert_dir);

    // Initiate services
    let constraints = ConstraintStore::new();
    let event_sender = init_event_watcher(&client);
    let mut manager = Manager::new(client.clone(), constraints.clone(), event_sender.clone());
    let evaluator = ConstraintEvaluator::new(constraints.clone(), event_sender.clone());
    manager.start().await;
    manager.load_existing_constraints().await;

    if args.audit {
        crate::audit::launch_loop(client, constraints, args.audit_interval.unwrap_or(600)).await;
    }

    // Launch API with webhook endpoint
    crate::api::server(cert, evaluator).await;
}
