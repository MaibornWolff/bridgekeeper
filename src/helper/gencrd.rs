use crate::{constants::CRD_FILEPATH, crd::Policy, crd::Module};
use argh::FromArgs;
use kube::CustomResourceExt;
use std::fs;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;

#[derive(FromArgs, PartialEq, Eq, Debug)]
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
    let policy_crd = Policy::crd();
    let module_crd = Module::crd();
    let filepath = args.file.unwrap_or_else(|| CRD_FILEPATH.to_string());

    let mut crd = String::new();
    crd.push_str(&gen_crd_data(&policy_crd));
    crd.push_str(&gen_crd_data(&module_crd));
    write_crd_str(&filepath, &crd, args.no_wrapping);
}

fn gen_crd_data(data: &CustomResourceDefinition) -> String {
    let mut string_data = serde_yaml::to_string(data).expect("Could not generate yaml from CRD definition");
    string_data.push_str("---\n");

    string_data
}

fn write_crd_str(filepath: &str, data: &str, no_wrapping: bool) {
    if filepath == "-" {
        println!("{}\n", data);
    } else {

        let wrapped_data = "{{- if .Values.installCRDs }}\n".to_string() + &data + "{{- end }}\n";
        
        fs::write(
            filepath,
            match no_wrapping {
                true => data,
                false => &wrapped_data,
            },
        )
        .expect("Unable to write crd yaml");
    }
}