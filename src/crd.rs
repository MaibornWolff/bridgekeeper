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
#[kube(status = "ConstraintStatus")]
pub struct ConstraintSpec {
    pub target: Target,
    pub rule: Rule,
    pub audit: Option<bool>,
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

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConstraintStatus {
    pub audit: Option<AuditStatus>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditStatus {
    pub timestamp: Option<String>,
    pub violations: Option<Vec<Violation>>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Violation {
    pub identifier: String,
    pub message: String,
}

impl ConstraintStatus {
    pub fn new() -> ConstraintStatus {
        ConstraintStatus {
            audit: Some(AuditStatus::new()),
        }
    }
}

impl AuditStatus {
    pub fn new() -> AuditStatus {
        AuditStatus {
            timestamp: None,
            violations: None,
        }
    }
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
            audit: Some(false),
            target,
            rule: Default::default(),
        }
    }
}
