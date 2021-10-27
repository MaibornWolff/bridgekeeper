use argh::FromArgs;

mod api;
mod audit;
mod constants;
mod constraint;
mod crd;
mod evaluator;
mod events;
mod helper;
mod manager;
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

#[tokio::main]
async fn main() {
    let args: MainArgs = argh::from_env();
    let log_level = match args.command {
        CommandEnum::Server(_) => log::LevelFilter::Info,
        _ => log::LevelFilter::Error,
    };
    simple_logger::SimpleLogger::new()
        .with_level(log_level)
        .with_module_level("rocket::server", log::LevelFilter::Warn)
        .with_module_level("_", log::LevelFilter::Warn)
        .init()
        .unwrap();
    match args.command {
        CommandEnum::Server(args) => server::run(args).await,
        CommandEnum::Init(args) => helper::init::run(args).await,
        CommandEnum::Cleanup(args) => helper::cleanup::run(args).await,
        CommandEnum::Audit(args) => audit::run(args).await,
        CommandEnum::GenCRD(args) => helper::gencrd::run(args),
    }
}
