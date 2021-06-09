use crate::constraint::ConstraintObjectReference;
use k8s_openapi::api::core::v1::{Event as KubeEvent, EventSource as KubeEventSource};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use k8s_openapi::chrono::offset::Utc;
use kube::{
    api::{Api, PostParams},
    Client,
};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task;

pub type EventSender = UnboundedSender<ConstraintEvent>;

#[derive(Debug)]
pub struct ConstraintEvent {
    pub constraint_reference: ConstraintObjectReference,
    pub event_data: ConstraintEventData,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConstraintEventData {
    LOADED,
    EVALUATED {
        target_identifier: String,
        result: bool,
        reason: Option<String>,
    },
}

pub fn init_event_watcher(client: &Client) -> EventSender {
    let (sender, mut receiver) = mpsc::unbounded_channel::<ConstraintEvent>();
    let namespace = std::env::var("NAMESPACE").unwrap_or("default".to_string());
    let events_api: Api<KubeEvent> = Api::namespaced(client.clone(), &namespace);
    task::spawn(async move {
        let instance = std::env::var("POD_NAME").unwrap_or("dev".to_string());
        while let Some(event) = receiver.recv().await {
            let mut kube_event = KubeEvent::default();
            kube_event.metadata.generate_name = event.constraint_reference.name.clone();
            kube_event.involved_object = event.constraint_reference.to_object_reference();
            kube_event.type_ = Some("Normal".to_string());
            kube_event.first_timestamp = Some(Time(Utc::now()));
            kube_event.source = Some(KubeEventSource {
                component: Some(format!("bridgekeeper/{}", instance)),
                host: None,
            });
            match event.event_data {
                ConstraintEventData::LOADED => {
                    kube_event.reason = Some("Loaded".to_string());
                    kube_event.message = Some(format!("Constraint loaded by bridgekeeper"));
                }
                ConstraintEventData::EVALUATED {
                    target_identifier,
                    result,
                    reason,
                } => {
                    kube_event.reason = Some("Evaluated".to_string());
                    kube_event.message = Some(format!(
                        "Target: {}, Result: {}, Reason: {}",
                        target_identifier,
                        result,
                        reason.unwrap_or("-".to_string())
                    ));
                }
            }
            if let Err(_err) = events_api.create(&PostParams::default(), &kube_event).await {
                log::warn!(
                    "Could not create event for constraint {}",
                    event
                        .constraint_reference
                        .name
                        .clone()
                        .unwrap_or("-".to_string())
                );
            }
        }
    });
    sender
}
