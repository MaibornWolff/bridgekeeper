use exponential_backoff::Backoff;
use kube::{
    api::{Api, ListParams, Patch, PatchParams},
    core::ObjectList,
};
use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use std::time::Duration;

lazy_static! {
    static ref BACKOFF: Backoff =
        Backoff::new(4, Duration::from_millis(100), Duration::from_secs(2));
}

pub async fn list_with_retry<T>(api: &Api<T>, params: ListParams) -> kube::Result<ObjectList<T>>
where
    T: DeserializeOwned + Clone + std::fmt::Debug,
{
    for duration in BACKOFF.iter() {
        match api.list(&params).await {
            Ok(result) => return Ok(result),
            Err(_err) => tokio::time::sleep(duration).await,
        }
    }
    api.list(&params).await
}

pub async fn patch_status_with_retry<
    T: DeserializeOwned + Clone + std::fmt::Debug,
    P: serde::Serialize + std::fmt::Debug,
>(
    api: &Api<T>,
    name: &str,
    pp: &PatchParams,
    patch: &Patch<P>,
) -> kube::Result<T> {
    for duration in BACKOFF.iter() {
        match api.patch_status(&name, &pp, &patch).await {
            Ok(result) => return Ok(result),
            Err(_err) => tokio::time::sleep(duration).await,
        }
    }
    api.patch_status(&name, &pp, &patch).await
}
