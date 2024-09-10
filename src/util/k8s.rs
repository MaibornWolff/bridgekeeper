use exponential_backoff::Backoff;
use kube::{
    api::{Api, ListParams, Patch, PatchParams},
    core::ObjectList,
    core::{ApiResource as KubeApiResource, GroupVersionKind},
    Client, Resource,
};
use lazy_static::lazy_static;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

use crate::util::error::{kube_err, Result};
use k8s_openapi::{
    api::core::v1::Namespace,
    apimachinery::pkg::apis::meta::v1::{APIGroup, APIResource},
};

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
            Err(_err) => match duration {
                Some(duration) => tokio::time::sleep(duration).await,
                None => break,
            }
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
            Err(_err) => match duration {
                Some(duration) => tokio::time::sleep(duration).await,
                None => break,
            }
        }
    }
    api.patch_status(name, pp, patch).await
}

pub async fn apply<T>(api: &Api<T>, name: &str, mut object: T) -> kube::Result<T>
where
    <T as Resource>::DynamicType: Default,
    T: Resource,
    T: Clone,
    T: Serialize,
    T: DeserializeOwned,
    T: std::fmt::Debug,
{
    if let Ok(res) = api.get(name).await {
        object
            .meta_mut()
            .resource_version
            .clone_from(&res.meta().resource_version);
        api.replace(name, &Default::default(), &object).await
    } else {
        api.create(&Default::default(), &object).await
    }
}

pub async fn find_k8s_resource_matches(
    api_group: &str,
    kind: &str,
    client: &Client,
) -> Result<Vec<(KubeApiResource, bool)>> {
    let mut matched_resources = Vec::new();
    // core api group
    if api_group.is_empty() {
        let versions = client.list_core_api_versions().await.map_err(kube_err)?;
        let version = versions
            .versions
            .first()
            .expect("core api group always has a version");
        let resources = client
            .list_core_api_resources(version)
            .await
            .map_err(kube_err)?;
        for resource in resources.resources.iter() {
            if (kind == "*" || resource.kind.to_lowercase() == kind.to_lowercase())
                && !resource.name.contains('/')
            {
                matched_resources.push((
                    gen_resource_description(None, resource, Some(version.clone())),
                    resource.namespaced,
                ));
            }
        }
    } else {
        for group in client
            .list_api_groups()
            .await
            .map_err(kube_err)?
            .groups
            .iter()
        {
            if api_group == "*" || group.name.to_lowercase() == api_group.to_lowercase() {
                let api_version = group
                    .preferred_version
                    .clone()
                    .expect("API Server always has a preferred_version")
                    .group_version;
                for resource in client
                    .list_api_group_resources(&api_version)
                    .await
                    .map_err(kube_err)?
                    .resources
                    .iter()
                {
                    if (kind == "*" || resource.kind.to_lowercase() == kind.to_lowercase())
                        && !resource.name.contains('/')
                    {
                        matched_resources.push((
                            gen_resource_description(Some(group), resource, None),
                            resource.namespaced,
                        ));
                    }
                }
            }
        }
    }
    Ok(matched_resources)
}

pub fn gen_resource_description(
    api_group: Option<&APIGroup>,
    api_resource: &APIResource,
    version: Option<String>,
) -> KubeApiResource {
    let gvk = GroupVersionKind {
        group: match api_group {
            Some(group) => group.name.clone(),
            None => String::from(""),
        },
        version: match api_group {
            Some(group) => {
                group
                    .preferred_version
                    .clone()
                    .expect("API Server always has a preferred_version")
                    .version
            }
            None => version.unwrap_or_default(),
        },
        kind: api_resource.kind.clone(),
    };
    KubeApiResource::from_gvk_with_plural(&gvk, &api_resource.name)
}

pub async fn namespaces(k8s_client: Client) -> Result<Vec<String>> {
    let mut namespaces = Vec::new();
    let namespace_api: Api<Namespace> = Api::all(k8s_client);
    let result = namespace_api
        .list(&ListParams::default())
        .await
        .map_err(kube_err)?;
    for namespace in result.iter() {
        if !namespace
            .metadata
            .labels
            .as_ref()
            .map_or(false, |map| map.contains_key("bridgekeeper/ignore"))
        {
            namespaces.push(
                namespace
                    .metadata
                    .name
                    .clone()
                    .expect("Each object has a name"),
            );
        }
    }
    Ok(namespaces)
}
