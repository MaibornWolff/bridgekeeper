use crate::util::error::{kube_err, Result};
use k8s_openapi::{api::core::v1::Namespace, apimachinery::pkg::apis::meta::v1::{APIGroup, APIResource}};
use kube::{
    core::{ApiResource as KubeApiResource, DynamicObject, GroupVersionKind},
    Client, api::ListParams, Api, Resource
};

pub async fn find_k8s_resource_matches(
    api_group: &str,
    kind: &str,
    client: &Client
) -> Result<Vec<(KubeApiResource, bool)>> {
    let mut matched_resources = Vec::new();
    // core api group
    if api_group.is_empty() {
        let versions = client
            .list_core_api_versions()
            .await
            .map_err(kube_err)?;
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
                    gen_resource_description(None, resource),
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
                            gen_resource_description(Some(group), resource),
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
            None => String::from(""),
        },
        kind: api_resource.kind.clone(),
    };
    KubeApiResource::from_gvk_with_plural(&gvk, &api_resource.name)
}

pub fn gen_target_identifier(resource: &KubeApiResource, object: &DynamicObject) -> String {
    let meta = object.meta();
    format!(
        "{}/{}/{}/{}",
        resource.group,
        resource.kind,
        meta.namespace.clone().unwrap_or_else(|| "-".to_string()),
        meta.name.clone().expect("Each object has a name")
    )
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