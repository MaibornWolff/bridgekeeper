use k8s_openapi::api::core::v1::ObjectReference as KubeObjectReference;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ObjectReference {
    pub api_version: Option<String>,
    pub kind: Option<String>,
    pub name: Option<String>,
    pub uid: Option<String>,
}

impl ObjectReference {
    pub fn to_object_reference(&self) -> KubeObjectReference {
        KubeObjectReference {
            api_version: self.api_version.clone(),
            kind: self.kind.clone(),
            name: self.name.clone(),
            uid: self.uid.clone(),
            ..Default::default()
        }
    }
}