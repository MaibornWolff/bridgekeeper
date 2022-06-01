use crate::{constants::CRD_FILEPATH, crd::Policy};
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
    /// do not wrap CRD yaml in helm template if condition
    #[argh(switch)]
    pub no_wrapping: bool,
}

pub fn run(args: Args) {
    let data = serde_yaml::to_string(&Policy::crd())
        .expect("Could not generate yaml from CRD definition");
    let filepath = args.file.unwrap_or_else(|| CRD_FILEPATH.to_string());
    let wrapped_data = "{{- if .Values.installCRDs }}\n".to_string() + &data + "{{- end }}\n";
    if filepath == "-" {
        println!("{}\n", data);
    } else {
        fs::write(
            filepath,
            match args.no_wrapping {
                true => data,
                false => wrapped_data,
            },
        )
        .expect("Unable to write crd yaml");
    }

}
