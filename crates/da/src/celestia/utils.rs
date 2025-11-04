use celestia_types::nmt::Namespace;
use prism_serde::hex::FromHex;

use crate::error::DataAvailabilityError;

pub fn create_namespace(namespace_hex: &str) -> Result<Namespace, DataAvailabilityError> {
    let decoded_hex = Vec::<u8>::from_hex(namespace_hex).map_err(|e| {
        DataAvailabilityError::InitializationError(format!(
            "Failed to decode namespace hex '{}': {}",
            namespace_hex, e
        ))
    })?;

    Namespace::new_v0(&decoded_hex).map_err(|e| {
        DataAvailabilityError::InitializationError(format!(
            "Failed to create namespace from '{}': {}",
            namespace_hex, e
        ))
    })
}
