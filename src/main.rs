use argh::FromArgs;

mod api;
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
}

#[tokio::main]
async fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .with_module_level("rocket::server", log::LevelFilter::Warn)
        .with_module_level("_", log::LevelFilter::Warn)
        .init()
        .unwrap();
    let args: MainArgs = argh::from_env();
    match args.command {
        CommandEnum::SERVER(args) => server::run(args).await,
        CommandEnum::INIT(args) => helper::init::run(args).await,
        CommandEnum::CLEANUP(args) => helper::cleanup::run(args).await,
    }
}
