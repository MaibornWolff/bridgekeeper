use kube::CustomResource;
use schemars::JsonSchema;
use serde_derive::{Deserialize, Serialize};

#[derive(
    CustomResource, Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq, JsonSchema,
)]
#[kube(
    group = "bridgekeeper.maibornwolff.de",
    version = "v1alpha1",
    kind = "Constraint"
)]
pub struct ConstraintSpec {
    pub target: Target,
    pub rule: Rule,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub matches: Vec<Match>,
    pub namespaces: Option<Vec<String>>,
    pub excluded_namespaces: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub api_group: String,
    pub kind: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, Hash, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub python: String,
}

#[cfg(test)]
impl Match {
    pub fn new(api_group: &str, kind: &str) -> Match {
        Match {
            api_group: api_group.to_string(),
            kind: kind.to_string(),
        }
    }
}

#[cfg(test)]
impl Target {
    pub fn from_match(r#match: Match) -> Target {
        Target {
            matches: vec![r#match],
            namespaces: None,
            excluded_namespaces: None,
        }
    }
}

#[cfg(test)]
impl ConstraintSpec {
    pub fn from_target(target: Target) -> ConstraintSpec {
        ConstraintSpec {
            target,
            rule: Default::default(),
        }
    }
}
