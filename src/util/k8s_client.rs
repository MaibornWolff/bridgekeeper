use exponential_backoff::Backoff;
use kube::{
    api::{Api, ListParams, Patch, PatchParams},
    core::ObjectList,
    Resource,
};
use lazy_static::lazy_static;
use serde::{de::DeserializeOwned, Serialize};
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
        match api.patch_status(name, pp, patch).await {
            Ok(result) => return Ok(result),
            Err(_err) => tokio::time::sleep(duration).await,
        }
    }
    api.patch_status(name, pp, patch).await
}

pub async fn apply<T: Resource>(api: &Api<T>, name: &str, mut object: T) -> kube::Result<T>
where
    <T as Resource>::DynamicType: Default,
    T: Clone,
    T: Serialize,
    T: DeserializeOwned,
    T: std::fmt::Debug,
{
    if let Ok(res) = api.get(name).await {
        object.meta_mut().resource_version = res.meta().resource_version.clone();
        api.replace(name, &Default::default(), &object).await
    } else {
        api.create(&Default::default(), &object).await
    }
}
