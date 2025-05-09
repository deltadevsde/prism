use lazy_static::lazy_static;
use opentelemetry::{global, metrics::{Counter, Gauge, Meter}};
use parking_lot::Mutex;
use tracing::info;

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
    pub last_epoch_produced_time: Gauge<u64>,
    pub transactions_processed_total: Counter<u64>,
    pub transactions_pending_total: Counter<u64>,
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

        let last_epoch_produced_time = meter
            .u64_gauge(format!("{}last_epoch_produced_time", prefix))
            .with_description("Last epoch produced time")
            .build();

        let transactions_processed_total = meter
            .u64_counter(format!("{}transactions_processed_total", prefix))
            .with_description("Total number of processed transactions, labeled by type and status")
            .build();

        let transactions_pending_total = meter
            .u64_counter(format!("{}transactions_pending_total", prefix))
            .with_description("Total number of pending transactions, labeled by type")
            .build();

        PrismMetrics {
            meter,
            node_info,
            celestia_synced_height,
            current_epoch,
            last_epoch_produced_time,
            transactions_processed_total,
            transactions_pending_total,
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

    /// Records the last epoch produced time with the given attributes.
    ///
    /// # Parameters
    /// * `time` - The last epoch produced time
    /// * `attributes` - Vector of key-value pairs to attach to the metric
    pub fn record_last_epoch_produced_time(&self, time: u64, attributes: Vec<(String, String)>) {
        self.last_epoch_produced_time.record(time, build_attributes(attributes).as_slice());
    }

    /// Records the total number of processed transactions with the given attributes.
    ///
    /// # Parameters
    /// * `transactions` - The total number of processed transactions
    /// * `attributes` - Vector of key-value pairs to attach to the metric
    pub fn count_processed_transactions(&self, transactions: u64, attributes: Vec<(String, String)>) {
        self.transactions_processed_total.add(transactions, build_attributes(attributes).as_slice());
    }

    /// Records the total number of pending transactions with the given attributes.
    ///
    /// # Parameters
    /// * `transactions` - The total number of pending transactions
    /// * `attributes` - Vector of key-value pairs to attach to the metric
    pub fn count_pending_transactions(&self, transactions: u64, attributes: Vec<(String, String)>) {
        self.transactions_pending_total.add(transactions, build_attributes(attributes).as_slice());
    }

}

// Global instance of PrismMetrics
lazy_static! {
    static ref METRICS: Mutex<Option<PrismMetrics>> = Mutex::new(None);
}

// Initialize the global metrics instance
pub fn init_metrics_registry() {
    let mut metrics = METRICS.lock();
    if metrics.is_none() {
        *metrics = Some(PrismMetrics::new());
        info!("Prism metrics registry initialized");
    }
}

// Get a reference to the metrics registry
pub fn get_metrics() -> Option<PrismMetrics> {
    match METRICS.try_lock() {
        Some(metrics) => metrics.clone(),
        None => {
            tracing::warn!("Failed to acquire lock for metrics registry");
            None
        }
    }
}

/// Records the last epoch produced time with the given attributes.
/// Intended to be called from other crates, passing the time as a u64.
pub fn record_last_epoch_produced_time_metric(time: u64) {
    if let Some(metrics) = get_metrics() {
        metrics.record_last_epoch_produced_time(time, vec![]);
    }
}

/// Records a processed transaction metric with the given transaction type and status.
/// Intended to be called from other crates, passing the operation type and status as strings.
pub fn record_processed_transaction_metric(transaction_type: &str, status: &str) {
    if let Some(metrics) = get_metrics() {
        metrics.count_processed_transactions(
            1,
            vec![
                ("transaction_type".to_string(), transaction_type.to_string()),
                ("status".to_string(), status.to_string()),
            ],
        );
    }
}

/// Records a pending transaction metric with the given transaction type.
/// Intended to be called from other crates, passing the operation type as a string.
pub fn record_pending_transaction_metric(transaction_type: &str) {
    if let Some(metrics) = get_metrics() {
        metrics.count_pending_transactions(
            1,
            vec![
                ("transaction_type".to_string(), transaction_type.to_string()),
            ],
        );
    }
}
