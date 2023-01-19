use argh::FromArgs;
use tracing::Level;

mod api;
mod audit;
mod constants;
mod crd;
mod evaluator;
mod events;
mod helper;
mod manager;
mod policy;
mod server;
mod util;

#[derive(FromArgs, PartialEq, Debug)]
/// bridgekeeper
struct MainArgs {
    #[argh(subcommand)]
    command: CommandEnum,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum CommandEnum {
    Server(server::Args),
    Init(helper::init::Args),
    Cleanup(helper::cleanup::Args),
    Audit(audit::Args),
    GenCRD(helper::gencrd::Args),
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: MainArgs = argh::from_env();

    let log_level = match args.command {
        CommandEnum::Server(_) => Level::INFO,
        _ => Level::ERROR,
    };

    let log_mode = std::env::var("LOGGING_MODE").unwrap_or_else(|_| "plain".into());

    if log_mode.to_lowercase().eq("json") {
        tracing_subscriber::fmt()
            .json()
            .with_max_level(log_level)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .init();
    }

    match args.command {
        CommandEnum::Server(args) => server::run(args).await,
        CommandEnum::Init(args) => helper::init::run(args).await,
        CommandEnum::Cleanup(args) => helper::cleanup::run(args).await,
        CommandEnum::Audit(args) => audit::run(args).await,
        CommandEnum::GenCRD(args) => helper::gencrd::run(args),
    }
}
