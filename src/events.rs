use k8s_openapi::api::core::v1::{Event as KubeEvent, EventSource as KubeEventSource};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use k8s_openapi::chrono::offset::Utc;
use kube::{
    api::{Api, PostParams},
    Client,
};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task;

use crate::util::types::ObjectReference;

pub type EventSender = UnboundedSender<Event>;

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyEventData {
    Loaded,
    Evaluated {
        target_identifier: String,
        result: bool,
        reason: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ModuleEventData {
    Loaded,
}

#[derive(Debug)]
pub enum EventType {
    Policy(PolicyEventData),
    Module(ModuleEventData),
}

#[derive(Debug)]
pub struct Event {
    pub object_reference: ObjectReference,
    pub event_data: EventType,
}

pub fn init_event_watcher(client: &Client) -> EventSender {
    let (sender, mut receiver) = mpsc::unbounded_channel::<Event>();
    let events_api: Api<KubeEvent> = Api::namespaced(client.clone(), "default");
    task::spawn(async move {
        let instance = std::env::var("POD_NAME").unwrap_or_else(|_| "dev".to_string());
        while let Some(event) = receiver.recv().await {
            let mut kube_event = KubeEvent::default();

            kube_event.metadata.generate_name = event.object_reference.name.clone();
            kube_event.involved_object = event.object_reference.to_object_reference();
            kube_event.type_ = Some("Normal".to_string());
            kube_event.first_timestamp = Some(Time(Utc::now()));
            kube_event.source = Some(KubeEventSource {
                component: Some(format!("bridgekeeper/{}", instance)),
                host: None,
            });

            match event.event_data {
                EventType::Policy(event_data) => {
                    match event_data {
                        PolicyEventData::Loaded => {
                            kube_event.reason = Some("Loaded".to_string());
                            kube_event.message = Some("Policy loaded by bridgekeeper".to_string());
                        }
                        PolicyEventData::Evaluated {
                            target_identifier,
                            result,
                            reason,
                        } => {
                            kube_event.reason = Some("Evaluated".to_string());
                            kube_event.message = Some(format!(
                                "Target: {}, Result: {}, Reason: {}",
                                target_identifier,
                                result,
                                reason.unwrap_or_else(|| "-".to_string())
                            ));
                        }
                    }
                },
                EventType::Module(event_data) => {
                    match event_data {
                        ModuleEventData::Loaded => {
                            kube_event.reason = Some("Loaded".to_string());
                            kube_event.message = Some("Module loaded by bridgekeeper".to_string());
                        }
                    }
                }
            }

            if let Err(err) = events_api.create(&PostParams::default(), &kube_event).await {
                log::warn!(
                    "Could not create event for policy {}. Reason: {}",
                    event
                        .object_reference
                        .name
                        .clone()
                        .unwrap_or_else(|| "-".to_string()),
                    err
                );
            }
        }
    });
    sender
}
