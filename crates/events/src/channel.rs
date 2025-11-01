use tokio::sync::broadcast;
use web_time::SystemTime;

use crate::{EventInfo, PrismEvent};

const EVENT_CHANNEL_CAPACITY: usize = 1024;

// The event channel that components use to broadcast events
#[derive(Debug, Clone)]
pub struct EventChannel {
    tx: broadcast::Sender<EventInfo>,
}

impl Default for EventChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl EventChannel {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self { tx }
    }

    pub fn publisher(&self) -> EventPublisher {
        EventPublisher {
            tx: self.tx.clone(),
        }
    }

    pub fn subscribe(&self) -> EventSubscriber {
        EventSubscriber {
            rx: self.tx.subscribe(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventPublisher {
    tx: broadcast::Sender<EventInfo>,
}

impl EventPublisher {
    pub fn send(&self, event: PrismEvent) {
        let formatted_log = event.to_string();
        let event_info = EventInfo {
            event,
            time: SystemTime::now(),
            formatted_log,
        };
        let _ = self.tx.send(event_info);
    }
}

#[derive(Debug)]
pub struct EventSubscriber {
    rx: broadcast::Receiver<EventInfo>,
}

impl EventSubscriber {
    pub async fn recv(&mut self) -> Result<EventInfo, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
