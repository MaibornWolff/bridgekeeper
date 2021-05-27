use argh::FromArgs;
use tokio::task;

use crate::constants::POD_CERTS_DIR;

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

    // Launch watcher
    let mut watcher = crate::watcher::Watcher::new(client);
    watcher.init().await;
    let constraints = watcher.get_constraints();
    task::spawn(async move {
        watcher.start().await;
    });

    // Launch API with webhook endpoint
    crate::api::server(cert, constraints).await;
}
