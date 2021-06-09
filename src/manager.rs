use crate::constraint::ConstraintStoreRef;
use crate::{
    crd::Constraint,
    events::{ConstraintEvent, ConstraintEventData, EventSender},
};
use futures::StreamExt;
use kube::{
    api::{Api, ListParams},
    Client,
};
use kube_runtime::{watcher, watcher::Event};
use tokio::task;

pub struct Manager {
    k8s_client: Client,
    constraints: ConstraintStoreRef,
    event_sender: EventSender,
}

impl Manager {
    pub fn new(
        client: Client,
        constraints: ConstraintStoreRef,
        event_sender: EventSender,
    ) -> Manager {
        Manager {
            k8s_client: client,
            constraints,
            event_sender,
        }
    }

    pub async fn load_existing_constraints(&mut self) {
        let constraints_api = self.constraints_api();
        let res = constraints_api.list(&ListParams::default()).await.unwrap();
        {
            let mut constraints = self.constraints.lock().unwrap();
            for constraint in res {
                let ref_info = constraints.add_constraint(constraint);
                self.event_sender
                    .send(ConstraintEvent {
                        constraint_reference: ref_info,
                        event_data: ConstraintEventData::LOADED,
                    })
                    .unwrap_or_else(|err| log::warn!("Could not send event: {:?}", err));
            }
        }
    }

    pub async fn start(&mut self) {
        let constraints_api = self.constraints_api();
        let constraints = self.constraints.clone();
        let event_sender = self.event_sender.clone();

        task::spawn(async move {
            let watcher = watcher(constraints_api.clone(), ListParams::default());
            let mut pinned_watcher = Box::pin(watcher);
            loop {
                let res = pinned_watcher.next().await;
                if let Some(Ok(event)) = res {
                    match event {
                        Event::Applied(constraint) => {
                            let mut constraints = constraints.lock().unwrap();
                            let ref_info = constraints.add_constraint(constraint);
                            event_sender
                                .send(ConstraintEvent {
                                    constraint_reference: ref_info,
                                    event_data: ConstraintEventData::LOADED,
                                })
                                .unwrap_or_else(|err| {
                                    log::warn!("Could not send event: {:?}", err)
                                });
                        }
                        Event::Deleted(constraint) => {
                            let mut constraints = constraints.lock().unwrap();
                            constraints.remove_constraint(constraint);
                        }
                        _ => (),
                    }
                }
            }
        });
    }

    fn constraints_api(&mut self) -> Api<Constraint> {
        Api::all(self.k8s_client.clone())
    }
}
