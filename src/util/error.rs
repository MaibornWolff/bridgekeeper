#[derive(Debug)]
pub enum BridgekeeperError {
    KubernetesError(String),
}

pub type Result<T> = std::result::Result<T, BridgekeeperError>;

impl std::fmt::Display for BridgekeeperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgekeeperError::KubernetesError(reason) => {
                f.write_fmt(format_args!("KubernetesError: {}", reason))
            }
        }
    }
}

pub fn kube_err<T: std::fmt::Display>(err: T) -> BridgekeeperError {
    return BridgekeeperError::KubernetesError(format!("{}", err));
}
