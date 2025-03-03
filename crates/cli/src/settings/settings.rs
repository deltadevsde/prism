use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::settings::models::Settings;

/// SettingsBuilder represents the raw configuration from different sources
/// before being converted to the strongly-typed Settings structure
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SettingsBuilder {
    /// Raw configuration data
    data: HashMap<String, serde_json::Value>,
}

impl SettingsBuilder {
    /// Create a new SettingsBuilder instance from a serializable config
    pub fn new<T: Serialize>(config: T) -> Self {
        let value = serde_json::to_value(config)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));

        match value {
            serde_json::Value::Object(map) => {
                let data = map.into_iter().collect();
                SettingsBuilder { data }
            },
            _ => SettingsBuilder::default(),
        }
    }

    /// Merge another settings object into this one, with the other taking precedence
    pub fn merge(&mut self, other: SettingsBuilder) {
        for (key, value) in other.data {
            self.merge_value(key, value);
        }
    }

    /// Helper method to merge a specific value
    fn merge_value(&mut self, key: String, value: serde_json::Value) {
        // Only attempt deep merge if both values are objects
        if let (Some(serde_json::Value::Object(existing)), serde_json::Value::Object(incoming)) =
            (self.data.get(&key).cloned(), value.clone()) {

            // Create a merged object
            let mut merged_obj = serde_json::Map::new();

            // Start with all existing values
            for (k, v) in existing {
                merged_obj.insert(k, v);
            }

            // Apply incoming values, using recursive merge for nested objects
            for (k, v) in incoming {
                if let (Some(serde_json::Value::Object(existing_nested)), serde_json::Value::Object(incoming_nested)) =
                    (merged_obj.get(&k).cloned().map(|val| match val {
                        serde_json::Value::Object(obj) => serde_json::Value::Object(obj),
                        _ => val
                    }), v.clone()) {

                    // Handle nested objects by creating temporary SettingsBuilder objects and merging them
                    let existing_map: HashMap<String, serde_json::Value> = existing_nested.into_iter().collect();
                    let incoming_map: HashMap<String, serde_json::Value> = incoming_nested.into_iter().collect();

                    let mut nested = SettingsBuilder { data: existing_map };
                    nested.merge(SettingsBuilder { data: incoming_map });

                    // Convert back to Value and insert
                    if let Ok(merged_value) = serde_json::to_value(nested.data) {
                        merged_obj.insert(k, merged_value);
                    }
                } else {
                    // For non-objects or mixed types, incoming value wins
                    merged_obj.insert(k, v);
                }
            }

            self.data.insert(key, serde_json::Value::Object(merged_obj));
        } else {
            // For non-objects, just replace the value
            self.data.insert(key, value);
        }
    }

    /// Convert SettingsBuilder to a strongly-typed Settings
    pub fn to_settings(&self) -> Result<Settings> {
        serde_json::to_value(&self.data)
            .context("Failed to convert settings to JSON")
            .and_then(|json| {
                serde_json::from_value(json)
                    .context("Failed to deserialize Settings from raw settings")
            })
    }
}
