use lazy_static::lazy_static;
use opentelemetry::{global, metrics::{Gauge, Meter}};
use parking_lot::Mutex;
use tracing::info;
use std::sync::Arc;

use crate::telemetry::build_attributes;

// Struct to hold all metrics
#[derive(Clone)]
pub struct PrismMetrics {
    // Note: meter field is kept even though it's not directly used
    // as it's needed to keep the meter provider alive
    #[allow(dead_code)]
    meter: Meter,
    // Celestia metrics
    pub node_info: Gauge<u64>,
    pub celestia_synced_height: Gauge<u64>,
    pub current_epoch: Gauge<u64>,
}

impl Default for PrismMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PrismMetrics {
    pub fn new() -> Self {
        info!("Initializing Prism metrics registry");
        let meter = global::meter("prism");

        let prefix = "prism_";

        let node_info = meter
            .u64_gauge(format!("{}node_info", prefix))
            .with_description("Prism node info")
            .build();

        let celestia_synced_height = meter
            .u64_gauge(format!("{}celestia_synced_height", prefix))
            .with_description("Celestia synced height")
            .build();

        let current_epoch = meter
            .u64_gauge(format!("{}current_epoch", prefix))
            .with_description("Celestia current epoch")
            .build();

        PrismMetrics {
            meter,
            node_info,
            celestia_synced_height,
            current_epoch,
        }
    }

    /// Records basic node information with the given attributes.
    ///
    /// # Parameters
    /// * `attributes` - Vector of key-value pairs to attach to the metric
    pub fn record_node_info(&self, attributes: Vec<(String, String)>) {
        self.node_info.record(1, build_attributes(attributes).as_slice());
    }

    /// Records the current Celestia synced height with the given attributes.
    ///
    /// # Parameters
    /// * `height` - The current synced height value
    /// * `attributes` - Vector of key-value pairs to attach to the metric
    pub fn record_celestia_synced_height(&self, height: u64, attributes: Vec<(String, String)>) {
        self.celestia_synced_height.record(height, build_attributes(attributes).as_slice());
    }

    /// Records the current epoch with the given attributes.
    ///
    /// # Parameters
    /// * `epoch` - The current epoch value
    /// * `attributes` - Vector of key-value pairs to attach to the metric
    pub fn record_current_epoch(&self, epoch: u64, attributes: Vec<(String, String)>) {
        self.current_epoch.record(epoch, build_attributes(attributes).as_slice());
    }
}

// Global instance of PrismMetrics
lazy_static! {
    static ref METRICS: Mutex<Option<Arc<PrismMetrics>>> = Mutex::new(None);
}

// Initialize the global metrics instance
pub fn init_metrics_registry() {
    let mut metrics = METRICS.lock();
    if metrics.is_none() {
        *metrics = Some(Arc::new(PrismMetrics::new()));
        info!("Prism metrics registry initialized");
    }
}

// Get a reference to the metrics registry
pub fn get_metrics() -> Option<Arc<PrismMetrics>> {
    match METRICS.try_lock() {
        Some(guard) => guard.clone(),
        None => {
            tracing::warn!("Failed to acquire lock for metrics registry");
            None
        }
    }
}
