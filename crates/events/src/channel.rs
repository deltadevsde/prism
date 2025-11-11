#[cfg(any(test, feature = "testing"))]
use prism_cross_target::time::Interval;
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

#[derive(Debug, thiserror::Error)]
pub enum EventSubscriberError {
    #[error("Channel lagged: {0} messages were skipped")]
    Lagged(u64),
    #[error("Channel closed")]
    Closed,
    #[error("Operation timed out")]
    Timeout,
}

impl From<broadcast::error::RecvError> for EventSubscriberError {
    fn from(err: broadcast::error::RecvError) -> Self {
        match err {
            broadcast::error::RecvError::Lagged(n) => Self::Lagged(n),
            broadcast::error::RecvError::Closed => Self::Closed,
        }
    }
}

#[derive(Debug)]
pub struct EventSubscriber {
    rx: broadcast::Receiver<EventInfo>,
}

impl EventSubscriber {
    pub async fn recv(&mut self) -> Result<EventInfo, EventSubscriberError> {
        Ok(self.rx.recv().await?)
    }

    #[cfg(any(test, feature = "testing"))]
    pub async fn wait_for_event<F>(
        &mut self,
        predicate: F,
        timeout: std::time::Duration,
    ) -> Result<(), EventSubscriberError>
    where
        F: Fn(&PrismEvent) -> bool,
    {
        let mut interval = Interval::new(timeout).await;

        loop {
            tokio::select! {
                result = self.recv() => {
                    let event_info = result?;
                    if predicate(&event_info.event) {
                        return Ok(());
                    }
                }
                _ = interval.tick() => {
                    return Err(EventSubscriberError::Timeout);
                }
            }
        }
    }
}
