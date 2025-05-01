use lazy_static::lazy_static;
use opentelemetry::{global, metrics::{Gauge, Meter}, KeyValue};
use std::sync::Mutex;
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
    pub start_height: Gauge<u64>,
    pub celestia_synced_height: Gauge<u64>,
    pub current_epoch: Gauge<u64>,
    // Add more metrics as needed
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
        
        let start_height = meter
            .u64_gauge("prism_start_height")
            .with_description("Celestia start height")
            .build();
            
        let celestia_synced_height = meter
            .u64_gauge("prism_celestia_synced_height")
            .with_description("Celestia synced height")
            .build();
            
        let current_epoch = meter
            .u64_gauge("prism_current_epoch")
            .with_description("Celestia current epoch")
            .build();
        
        PrismMetrics {
            meter,
            start_height,
            celestia_synced_height,
            current_epoch,
        }
    }
    
    // Helper method to record start height
    pub fn record_start_height(&self, height: u64, attributes: Vec<KeyValue>    ) {
        self.start_height.record(height, build_attributes(attributes).as_slice());
    }
    
    // Helper method to record Celestia synced height
    pub fn record_celestia_synced_height(&self, height: u64, attributes: Vec<KeyValue>) {
        self.celestia_synced_height.record(height, build_attributes(attributes).as_slice());
    }
    
    // Helper method to record current epoch
    pub fn record_current_epoch(&self, epoch: u64, attributes: Vec<KeyValue>) {
        self.current_epoch.record(epoch, build_attributes(attributes).as_slice());
    }
}

// Global instance of PrismMetrics
lazy_static! {
    static ref METRICS: Mutex<Option<PrismMetrics>> = Mutex::new(None);
}

// Initialize the global metrics instance
pub fn init_metrics_registry() {
    if let Ok(mut metrics) = METRICS.lock() {
        if metrics.is_none() {
            *metrics = Some(PrismMetrics::new());
            info!("Prism metrics registry initialized");
        }
    } else {
        tracing::error!("Failed to acquire lock for initializing metrics registry");
    }
}

// Get a reference to the metrics registry
pub fn get_metrics() -> Option<PrismMetrics> {
    match METRICS.lock() {
        Ok(metrics) => metrics.clone(),
        Err(_) => {
            tracing::error!("Failed to acquire lock for reading metrics registry");
            None
        }
    }
}
