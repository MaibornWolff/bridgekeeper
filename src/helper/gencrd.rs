use crate::{constants::CRD_FILEPATH, crd::Constraint};
use argh::FromArgs;
use kube::CustomResourceExt;
use std::fs;

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "gencrd")]
/// Generate crd yaml
pub struct Args {
    /// file to write yaml to
    #[argh(option, short = 'f')]
    pub file: Option<String>,
}

pub fn run(args: Args) {
    let data = serde_yaml::to_string(&Constraint::crd())
        .expect("Could not generate yaml from CRD definition");
    let filepath = args.file.unwrap_or(CRD_FILEPATH.to_string());
    fs::write(filepath, data).expect("Unable to write crd yaml");
}
