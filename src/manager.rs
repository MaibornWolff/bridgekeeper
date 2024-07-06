use crate::util::error::{kube_err, Result};
use crate::{
    crd::Policy,
    events::{EventSender, PolicyEvent, PolicyEventData},
    policy::PolicyStoreRef,
};
use futures::StreamExt;
use kube::runtime::{
    watcher,
    watcher::{Config as WatcherConfig, Event},
};
use kube::{
    api::{Api, ListParams},
    Client,
};
use tokio::task;
use tracing::warn;

pub struct Manager {
    k8s_client: Client,
    policies: PolicyStoreRef,
    event_sender: EventSender,
}

impl Manager {
    pub fn new(client: Client, policies: PolicyStoreRef, event_sender: EventSender) -> Manager {
        Manager {
            k8s_client: client,
            policies,
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
                if let Some(ref_info) = policies.add_policy(policy) {
                    self.event_sender
                        .send(PolicyEvent {
                            policy_reference: ref_info,
                            event_data: PolicyEventData::Loaded,
                        })
                        .unwrap_or_else(|err| warn!("Could not send event: {:?}", err));
                }
            }
        }
        Ok(())
    }

    pub async fn start(&mut self) {
        let policies_api = self.policies_api();
        let policies = self.policies.clone();
        let event_sender = self.event_sender.clone();

        task::spawn(async move {
            let watcher = watcher(policies_api.clone(), WatcherConfig::default());
            let mut pinned_watcher = Box::pin(watcher);
            let mut initial_policies_list: Option<Vec<Policy>> = None;
            loop {
                let res = pinned_watcher.next().await;
                if let Some(Ok(event)) = res {
                    match event {
                        Event::Init => {
                            initial_policies_list = Some(Vec::new());
                        }
                        Event::InitDone => {
                            if let Some(initial_policies_list) = initial_policies_list.take() {
                                let mut policies =
                                    policies.lock().expect("lock failed. Cannot continue");
                                policies.replace_policies(initial_policies_list);
                            }
                        }
                        Event::InitApply(policy) => {
                            initial_policies_list.get_or_insert_with(||Vec::new()).push(policy);
                        }
                        Event::Apply(policy) => {
                            if let Some(initial_policies_list) = initial_policies_list.as_mut() {
                                // We are in the init phase, buffer new policies
                                initial_policies_list.push(policy);
                                break;
                            }
                            let mut policies =
                                policies.lock().expect("lock failed. Cannot continue");
                            if let Some(ref_info) = policies.add_policy(policy) {
                                event_sender
                                    .send(PolicyEvent {
                                        policy_reference: ref_info,
                                        event_data: PolicyEventData::Loaded,
                                    })
                                    .unwrap_or_else(|err| warn!("Could not send event: {:?}", err));
                            }
                        }
                        Event::Delete(policy) => {
                            let mut policies =
                                policies.lock().expect("lock failed. Cannot continue");
                            policies.remove_policy(policy);
                        }
                    }
                }
            }
        });
    }

    fn policies_api(&mut self) -> Api<Policy> {
        Api::all(self.k8s_client.clone())
    }
}
