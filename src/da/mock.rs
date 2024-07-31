use crate::{
    common::Operation,
    error::{DataAvailabilityError, GeneralError},
};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    self,
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
};
use tokio::sync::Mutex;

use crate::da::{DataAvailabilityLayer, FinalizedEpoch};

/// The `NoopDataAvailabilityLayer` is a mock implementation of the `DataAvailabilityLayer` trait.
pub struct NoopDataAvailabilityLayer {}

#[async_trait]
impl DataAvailabilityLayer for NoopDataAvailabilityLayer {
    async fn get_latest_height(&self) -> Result<u64> {
        Ok(0)
    }

    async fn initialize_sync_target(&self) -> Result<u64> {
        Ok(0)
    }

    async fn get_snarks(&self, _: u64) -> Result<Vec<FinalizedEpoch>> {
        Ok(vec![])
    }

    async fn get_operations(&self, _: u64) -> Result<Vec<Operation>> {
        Ok(vec![])
    }

    async fn submit_operations(&self, _: Vec<Operation>) -> Result<u64> {
        Ok(0)
    }

    async fn submit_snarks(&self, _: Vec<FinalizedEpoch>) -> Result<u64> {
        Ok(0)
    }

    async fn start(&self) -> Result<()> {
        Ok(())
    }
}

/// The `LocalDataAvailabilityLayer` is a mock implementation of the `DataAvailabilityLayer` trait.
/// It simulates the behavior of a data availability layer, storing and retrieving epoch-objects in-memory only.
/// This allows to write and test the functionality of systems that interact with a data availability layer without the need for an actual external service or network like we do with Celestia.
///
/// This implementation is intended for testing and development only and should not be used in production environments. It provides a way to test the interactions with the data availability layer without the overhead of real network communication or data persistence.

pub struct LocalDataAvailabilityLayer {
    snark_height: AtomicU64,
    op_height: AtomicU64,
    file_lock: Mutex<()>,
}

impl Default for LocalDataAvailabilityLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalDataAvailabilityLayer {
    pub fn new() -> Self {
        LocalDataAvailabilityLayer {
            snark_height: AtomicU64::new(0),
            op_height: AtomicU64::new(0),
            file_lock: Mutex::new(()),
        }
    }

    fn get_file_path(&self, is_snark: bool) -> String {
        if is_snark {
            "snark_data.json".to_string()
        } else {
            "operations_data.json".to_string()
        }
    }

    async fn read_file(&self, is_snark: bool) -> Result<Value> {
        let _lock = self.file_lock.lock().await;
        let file_path = self.get_file_path(is_snark);
        let mut file = File::open(&file_path).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::InitializationError(format!(
                "Unable to open file {}: {}",
                file_path, e
            )))
        })?;

        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::InitializationError(format!(
                "Unable to read file {}: {}",
                file_path, e
            )))
        })?;

        let data: Value = serde_json::from_str(&contents).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::ParsingError(format!(
                "Invalid JSON format in file {}: {}",
                file_path, e
            )))
        })?;

        Ok(data)
    }

    async fn write_file(&self, is_snark: bool, data: &Value) -> Result<()> {
        let _lock = self.file_lock.lock().await;
        let file_path = self.get_file_path(is_snark);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .map_err(|e| {
                DataAvailabilityError::GeneralError(GeneralError::InitializationError(format!(
                    "Unable to open file {}: {}",
                    file_path, e
                )))
            })?;

        file.seek(std::io::SeekFrom::Start(0)).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::InitializationError(format!(
                "Unable to seek to start of file {}: {}",
                file_path, e
            )))
        })?;

        file.write_all(
            serde_json::to_string(data)
                .map_err(|e| {
                    DataAvailabilityError::GeneralError(GeneralError::ParsingError(e.to_string()))
                })?
                .as_bytes(),
        )
        .map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::InitializationError(format!(
                "Unable to write to file {}: {}",
                file_path, e
            )))
        })?;

        file.set_len(
            file.metadata()
                .map_err(|e| {
                    DataAvailabilityError::GeneralError(GeneralError::ParsingError(e.to_string()))
                })?
                .len(),
        )
        .map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::InitializationError(format!(
                "Unable to set file length for {}: {}",
                file_path, e
            )))
        })?;

        Ok(())
    }
}

#[async_trait]
impl DataAvailabilityLayer for LocalDataAvailabilityLayer {
    async fn get_latest_height(&self) -> Result<u64> {
        Ok(self.snark_height.load(Ordering::SeqCst))
    }

    async fn initialize_sync_target(&self) -> Result<u64> {
        Ok(0) // Always start at zero for testing purposes
    }

    async fn get_operations(&self, height: u64) -> Result<Vec<Operation>> {
        let data = self.read_file(false).await?;

        if let Some(operations) = data.get(height.to_string()) {
            let operations_hex = operations.as_str().ok_or_else(|| {
                DataAvailabilityError::GeneralError(GeneralError::ParsingError(
                    "Operations value is not a string".to_string(),
                ))
            })?;
            let operations_bytes = hex::decode(operations_hex).map_err(|e| {
                DataAvailabilityError::GeneralError(GeneralError::DecodingError(format!(
                    "Invalid hex string for operations: {}",
                    e
                )))
            })?;

            let result_operations: Vec<Operation> =
                borsh::from_slice(&operations_bytes).map_err(|e| {
                    DataAvailabilityError::GeneralError(GeneralError::DecodingError(format!(
                        "Wrong format for operations: {}",
                        e
                    )))
                })?;

            Ok(result_operations)
        } else {
            Err(anyhow!(DataAvailabilityError::DataRetrievalError(
                height,
                "Could not get operations from DA layer".to_string(),
            )))
        }
    }

    async fn submit_operations(&self, operations: Vec<Operation>) -> Result<u64> {
        let mut data = self.read_file(false).await?;
        let height = self.op_height.fetch_add(1, Ordering::SeqCst);

        let operations_hex = hex::encode(borsh::to_vec(&operations).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::EncodingError(format!(
                "Unable to serialize operations: {}",
                e
            )))
        })?);

        data[height.to_string()] = json!(operations_hex);
        self.write_file(false, &data).await?;

        Ok(height)
    }

    async fn get_snarks(&self, height: u64) -> Result<Vec<FinalizedEpoch>> {
        let data = self.read_file(true).await?;

        if let Some(epoch) = data.get(height.to_string()) {
            let epoch_hex = epoch.as_str().ok_or_else(|| {
                DataAvailabilityError::GeneralError(GeneralError::ParsingError(
                    "Epoch value is not a string".to_string(),
                ))
            })?;
            let epoch_bytes = hex::decode(epoch_hex).map_err(|e| {
                DataAvailabilityError::GeneralError(GeneralError::DecodingError(format!(
                    "Invalid hex string for epoch: {}",
                    e
                )))
            })?;

            let result_epoch: FinalizedEpoch = borsh::from_slice(&epoch_bytes).map_err(|e| {
                DataAvailabilityError::GeneralError(GeneralError::DecodingError(format!(
                    "Wrong format for epoch: {}",
                    e
                )))
            })?;

            Ok(vec![result_epoch])
        } else {
            Err(anyhow!(DataAvailabilityError::DataRetrievalError(
                height,
                "Could not get epoch from DA layer".to_string(),
            )))
        }
    }

    async fn submit_snarks(&self, epochs: Vec<FinalizedEpoch>) -> Result<u64> {
        assert_eq!(
            epochs.len(),
            1,
            "Only one epoch should be submitted at a time"
        );

        let epoch = epochs.into_iter().next().unwrap();
        let mut data = self.read_file(true).await?;

        let epoch_hex = hex::encode(borsh::to_vec(&epoch).map_err(|e| {
            DataAvailabilityError::GeneralError(GeneralError::EncodingError(format!(
                "Unable to serialize epoch: {}",
                e
            )))
        })?);

        data[epoch.height.to_string()] = json!(epoch_hex);
        self.write_file(true, &data).await?;

        self.snark_height.fetch_max(epoch.height, Ordering::SeqCst);
        Ok(epoch.height)
    }

    async fn start(&self) -> Result<()> {
        // No special initialization needed for the mock implementation
        Ok(())
    }
}
