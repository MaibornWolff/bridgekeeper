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
    SERVER(server::Args),
    INIT(helper::init::Args),
    CLEANUP(helper::cleanup::Args),
    AUDIT(audit::Args),
    GENCRD(helper::gencrd::Args),
}

#[tokio::main]
async fn main() {
    let args: MainArgs = argh::from_env();
    let log_level = match args.command {
        CommandEnum::SERVER(_) => log::LevelFilter::Info,
        _ => log::LevelFilter::Error,
    };
    simple_logger::SimpleLogger::new()
        .with_level(log_level)
        .with_module_level("rocket::server", log::LevelFilter::Warn)
        .with_module_level("_", log::LevelFilter::Warn)
        .init()
        .unwrap();
    match args.command {
        CommandEnum::SERVER(args) => server::run(args).await,
        CommandEnum::INIT(args) => helper::init::run(args).await,
        CommandEnum::CLEANUP(args) => helper::cleanup::run(args).await,
        CommandEnum::AUDIT(args) => audit::run(args).await,
        CommandEnum::GENCRD(args) => helper::gencrd::run(args),
    }
}
