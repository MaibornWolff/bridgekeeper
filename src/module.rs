use crate::crd::{Module, ModuleSpec};
use crate::util::traits::ObjectStore;
use crate::util::types::ObjectReference;
use kube::core::Resource;
use lazy_static::lazy_static;
use prometheus::{register_gauge, Gauge};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

lazy_static! {
    static ref ACTIVE_MODULES: Gauge =
        register_gauge!("bridgekeeper_modules_active", "Number of active modules.")
            .expect("creating metric always works");
}

pub struct ModuleStore {
    pub modules: HashMap<String, ModuleInfo>,
}

pub type ModuleStoreRef = Arc<Mutex<dyn ObjectStore<Module, HashMap<String, ModuleInfo>> + Send>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleInfo {
    pub name: String,
    pub module: ModuleSpec,
    pub ref_info: ObjectReference,
}

impl ModuleStore {
    pub fn new() -> ModuleStoreRef {
        let store = ModuleStore {
            modules: HashMap::new(),
        };
        Arc::new(Mutex::new(store))
    }
}

fn create_object_reference(obj: &Module) -> ObjectReference {
    ObjectReference {
        api_version: Some(Module::api_version(&()).to_string()),
        kind: Some(Module::kind(&()).to_string()),
        name: obj.metadata.name.clone(),
        uid: obj.metadata.uid.clone(),
    }
}

impl ModuleInfo {
    pub fn new(name: String, module: ModuleSpec, ref_info: ObjectReference) -> ModuleInfo {
        ModuleInfo {
            name,
            module,
            ref_info,
        }
    }
}

impl ObjectStore<Module, HashMap<String, ModuleInfo>> for ModuleStore {
    fn add_object(&mut self, module: Module) -> Option<ObjectReference> {
        let ref_info = create_object_reference(&module);
        let name = module.metadata.name.expect("name is always set");
        if let Some(existing_module_info) = self.modules.get(&name) {
            if existing_module_info.module != module.spec {
                let module_info = ModuleInfo::new(name.clone(), module.spec, ref_info.clone());
                log::info!("Module '{}' updated", name);
                self.modules.insert(name, module_info);
                Some(ref_info)
            } else {
                None
            }
        } else {
            let module_info = ModuleInfo::new(name.clone(), module.spec, ref_info.clone());
            log::info!("Module '{}' added", name);
            self.modules.insert(name, module_info);
            ACTIVE_MODULES.inc();
            Some(ref_info)
        }
    }

    fn remove_object(&mut self, module: Module) {
        let name = module.metadata.name.expect("name is always set");
        log::info!("Module '{}' removed", name);
        self.modules.remove(&name);
        ACTIVE_MODULES.dec();
    }

    fn get_objects(&self) -> HashMap<String, ModuleInfo> {
        return self.modules.clone();
    }
}