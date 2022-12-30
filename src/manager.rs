use crate::events::{EventType};
use crate::util::error::{kube_err, Result};
use crate::util::traits::ObjectStore;
use crate::{
    crd::Policy,
    crd::Module,
    events::{EventSender, Event, PolicyEventData, ModuleEventData},
    policy::PolicyStoreRef,
    module::ModuleStoreRef
};
use futures::StreamExt;
use kube::runtime::{watcher, watcher::Event as KubeEvent};
use kube::{
    api::{Api, ListParams},
    Client,
};
use tokio::task;

pub struct Manager {
    k8s_client: Client,
    policies: PolicyStoreRef,
    modules: ModuleStoreRef,
    event_sender: EventSender,
}

impl Manager {
    pub fn new(client: Client, policies: PolicyStoreRef, modules: ModuleStoreRef, event_sender: EventSender) -> Manager {
        Manager {
            k8s_client: client,
            policies,
            modules,
            event_sender,
        }
    }

    pub async fn load_existing_policies(&mut self) -> Result<()> {
        let policies_api = self.policies_api();
        let res = policies_api
            .list(&ListParams::default())
            .await
            .map_err(kube_err)?;
        {
            let mut policies = self.policies.lock().expect("lock failed. Cannot continue");
            for policy in res {
                if let Some(ref_info) = policies.add_object(policy) {
                    self.event_sender
                        .send(Event {
                            object_reference: ref_info,
                            event_data: EventType::Policy(PolicyEventData::Loaded),
                        })
                        .unwrap_or_else(|err| log::warn!("Could not send event: {:?}", err));
                }
            }
        }
        Ok(())
    }

    pub async fn load_existing_modules(&mut self) -> Result<()> {
        let modules_api = self.modules_api();
        let res = modules_api
            .list(&ListParams::default())
            .await
            .map_err(kube_err)?;
        {
            let mut modules = self.modules.lock().expect("lock failed. Cannot continue");
            for module in res {
                if let Some(ref_info) = modules.add_object(module) {
                    self.event_sender
                        .send(Event {
                            object_reference: ref_info,
                            event_data: EventType::Module(ModuleEventData::Loaded),
                        })
                        .unwrap_or_else(|err| log::warn!("Could not send event: {:?}", err));
                }
            }
        }
        Ok(())
    }

    pub async fn start(&mut self) {
        self.watch_policies();
        self.watch_modules();
    }

    fn watch_policies(&mut self) {
        let policies_api = self.policies_api();
        let policies = self.policies.clone();
        let event_sender = self.event_sender.clone();

        // Watcher for policies
        task::spawn(async move {
            let watcher = watcher(policies_api.clone(), ListParams::default());
            let mut pinned_watcher = Box::pin(watcher);
            loop {
                let res = pinned_watcher.next().await;
                if let Some(Ok(event)) = res {
                    match event {
                        KubeEvent::Applied(policy) => {
                            let mut policies =
                                policies.lock().expect("lock failed. Cannot continue");
                            if let Some(ref_info) = policies.add_object(policy) {
                                event_sender
                                    .send(Event {
                                        object_reference: ref_info,
                                        event_data: EventType::Policy(PolicyEventData::Loaded),
                                    })
                                    .unwrap_or_else(|err| {
                                        log::warn!("Could not send event: {:?}", err)
                                    });
                            }
                        }
                        KubeEvent::Deleted(policy) => {
                            let mut policies =
                                policies.lock().expect("lock failed. Cannot continue");
                            policies.remove_object(policy);
                        }
                        _ => (),
                    }
                }
            }
        });
    }

    fn watch_modules(&mut self) {
        let modules_api = self.modules_api();
        let modules = self.modules.clone();
        let event_sender = self.event_sender.clone();

        // Watcher for modules
        task::spawn(async move {
            let watcher = watcher(modules_api.clone(), ListParams::default());
            let mut pinned_watcher = Box::pin(watcher);
            loop {
                let res = pinned_watcher.next().await;
                if let Some(Ok(event)) = res {
                    match event {
                        KubeEvent::Applied(module) => {
                            let mut modules =
                                modules.lock().expect("lock failed. Cannot continue");
                            if let Some(ref_info) = modules.add_object(module) {
                                event_sender
                                    .send(Event {
                                        object_reference: ref_info,
                                        event_data: EventType::Module(ModuleEventData::Loaded),
                                    })
                                    .unwrap_or_else(|err| {
                                        log::warn!("Could not send event: {:?}", err)
                                    });
                            }
                        }
                        KubeEvent::Deleted(module) => {
                            let mut modules =
                                modules.lock().expect("lock failed. Cannot continue");
                            modules.remove_object(module);
                        }
                        _ => (),
                    }
                }
            }
        });
    }

    fn policies_api(&mut self) -> Api<Policy> {
        Api::all(self.k8s_client.clone())
    }

    fn modules_api(&mut self) -> Api<Module> {
        Api::all(self.k8s_client.clone())
    }
}
