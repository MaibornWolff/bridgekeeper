use crate::util::error::{kube_err, Result};
use crate::{
    constraint::ConstraintStoreRef,
    crd::Constraint,
    events::{ConstraintEvent, ConstraintEventData, EventSender},
};
use futures::StreamExt;
use kube::runtime::{watcher, watcher::Event};
use kube::{
    api::{Api, ListParams},
    Client,
};
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

    pub async fn load_existing_constraints(&mut self) -> Result<()> {
        let constraints_api = self.constraints_api();
        let res = constraints_api
            .list(&ListParams::default())
            .await
            .map_err(kube_err)?;
        {
            let mut constraints = self
                .constraints
                .lock()
                .expect("lock failed. Cannot continue");
            for constraint in res {
                if let Some(ref_info) = constraints.add_constraint(constraint) {
                    self.event_sender
                        .send(ConstraintEvent {
                            constraint_reference: ref_info,
                            event_data: ConstraintEventData::Loaded,
                        })
                        .unwrap_or_else(|err| log::warn!("Could not send event: {:?}", err));
                }
            }
        }
        Ok(())
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
                            let mut constraints =
                                constraints.lock().expect("lock failed. Cannot continue");
                            if let Some(ref_info) = constraints.add_constraint(constraint) {
                                event_sender
                                    .send(ConstraintEvent {
                                        constraint_reference: ref_info,
                                        event_data: ConstraintEventData::Loaded,
                                    })
                                    .unwrap_or_else(|err| {
                                        log::warn!("Could not send event: {:?}", err)
                                    });
                            }
                        }
                        Event::Deleted(constraint) => {
                            let mut constraints =
                                constraints.lock().expect("lock failed. Cannot continue");
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
