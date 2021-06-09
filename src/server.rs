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
}

pub async fn run(args: Args) {
    let client = kube::Client::try_default().await.unwrap();
    // Read certs
    let cert_dir = args.cert_dir.unwrap_or(POD_CERTS_DIR.to_string());
    let cert = crate::util::cert::wait_for_certs(cert_dir);

    // Initiate services
    let constraints = ConstraintStore::new();
    let event_sender = init_event_watcher(&client);
    let mut manager = Manager::new(client, constraints.clone(), event_sender.clone());
    let evaluator = ConstraintEvaluator::new(constraints.clone(), event_sender.clone());
    manager.start().await;
    manager.load_existing_constraints().await;

    // Launch API with webhook endpoint
    crate::api::server(cert, evaluator).await;
}
