use crate::error::DeimosResult;
use async_trait::async_trait;
use std::{self, sync::Arc};

pub mod lightclient;
pub mod sequencer;

#[async_trait]
pub trait NodeType {
    async fn start(self: Arc<Self>) -> DeimosResult<()>;
    // async fn stop(&self) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use crate::{storage::UpdateEntryJson, utils::verify_signature};
    use base64::{engine::general_purpose, Engine as _};

    fn setup_signature(valid_signature: bool) -> UpdateEntryJson {
        let signed_message = if valid_signature {
            "NRtq1sgoxllsPvljXZd5f4DV7570PdA9zWHa4ych2jBCDU1uUYXZvW72BS9O+C68hptk/4Y34sTJj4x92gq9DHsiaWQiOiJDb3NSWE9vU0xHN2E4c0NHeDc4S2h0ZkxFdWl5Tlk3TDRrc0Z0NzhtcDJNPSIsIm9wZXJhdGlvbiI6IkFkZCIsInZhbHVlIjoiMjE3OWM0YmIzMjc0NDQ1NGE0OTlhYTMwZTI0NTJlMTZhODcwMGQ5ODQyYjI5ZThlODcyN2VjMzczNWMwYjdhNiJ9".to_string()
        } else {
            "QVmk3wgoxllsPvljXZd5f4DV7570PdA9zWHa4ych2jBCDU1uUYXZvW72BS9O+C68hptk/4Y34sTJj4x92gq9DHsiaWQiOiJDb3NSWE9vU0xHN2E4c0NHeDc4S2h0ZkxFdWl5Tlk3TDRrc0Z0NzhtcDJNPSIsIm9wZXJhdGlvbiI6IkFkZCIsInZhbHVlIjoiMjE3OWM0YmIzMjc0NDQ1NGE0OTlhYTMwZTI0NTJlMTZhODcwMGQ5ODQyYjI5ZThlODcyN2VjMzczNWMwYjdhNiJ9".to_string()
        };
        let id_public_key = "CosRXOoSLG7a8sCGx78KhtfLEuiyNY7L4ksFt78mp2M=".to_string();

        UpdateEntryJson {
            id: id_public_key.clone(),
            signed_message,
            public_key: id_public_key,
        }
    }

    #[test]
    fn test_verify_valid_signature() {
        let signature_with_key = setup_signature(true);

        let result = verify_signature(
            &signature_with_key,
            Some(signature_with_key.public_key.clone()),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let signature_with_key = setup_signature(false);

        let result = verify_signature(
            &signature_with_key,
            Some(signature_with_key.public_key.clone()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_short_message() {
        let signature_with_key = setup_signature(true);

        let short_message = general_purpose::STANDARD.encode("this is a short message");

        let signature_with_key = UpdateEntryJson {
            signed_message: short_message,
            ..signature_with_key
        };

        let result = verify_signature(
            &signature_with_key,
            Some(signature_with_key.public_key.clone()),
        );
        assert!(result.is_err());
    }
}
