use argh::FromArgs;
use tracing::Level;
use tracing_subscriber::{filter, prelude::*};

mod api;
mod audit;
mod constants;
mod crd;
mod evaluator;
mod events;
mod helper;
mod manager;
mod policy;
mod module;
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

    let filter = filter::Targets::new()
        .with_target("rocket::server", Level::WARN)
        .with_target("_", Level::WARN) // From rocket, logs info about each request
        .with_target("rocket_http::tls::listener", Level::ERROR) // irrelevant infos about failed TLS handshakes
        .with_default(filter::LevelFilter::from_level(log_level));
    let subscriber = tracing_subscriber::registry().with(filter);

    let log_mode = std::env::var("LOGGING_MODE").unwrap_or_else(|_| "plain".to_string());
    if log_mode.to_lowercase().eq("json") {
        subscriber
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        subscriber.with(tracing_subscriber::fmt::layer()).init();
    }

    match args.command {
        CommandEnum::Server(args) => server::run(args).await,
        CommandEnum::Init(args) => helper::init::run(args).await,
        CommandEnum::Cleanup(args) => helper::cleanup::run(args).await,
        CommandEnum::Audit(args) => audit::run(args).await,
        CommandEnum::GenCRD(args) => helper::gencrd::run(args),
    }
}
