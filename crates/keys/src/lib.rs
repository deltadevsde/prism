mod signatures;
mod signing_keys;
mod verifying_keys;

pub use signatures::*;
pub use signing_keys::*;
pub use verifying_keys::*;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as engine, Engine as _};
    use ed25519_consensus::SigningKey as Ed25519SigningKey;
    use rand::rngs::OsRng;
    use secp256k1::SecretKey as Secp256k1SigningKey;

    #[test]
    fn test_reparsed_verifying_keys_are_equal_to_original() {
        let verifying_key_ed25519 = SigningKey::new_ed25519().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_bytes(
            verifying_key_ed25519.algorithm(),
            &verifying_key_ed25519.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_ed25519);

        let verifying_key_secp256k1 = SigningKey::new_secp256k1().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_bytes(
            verifying_key_secp256k1.algorithm(),
            &verifying_key_secp256k1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_secp256k1);

        let verifying_key_secp256r1 = SigningKey::new_secp256r1().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_bytes(
            verifying_key_secp256r1.algorithm(),
            &verifying_key_secp256r1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_secp256r1);
    }

    #[test]
    fn test_reparsed_signing_keys_are_equal_to_original() {
        let signing_key_ed25519 = SigningKey::new_ed25519();
        let re_parsed_signing_key = SigningKey::from_algorithm_and_bytes(
            signing_key_ed25519.algorithm(),
            &signing_key_ed25519.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signing_key, signing_key_ed25519);

        let signing_key_secp256k1 = SigningKey::new_secp256k1();
        let re_parsed_signing_key = SigningKey::from_algorithm_and_bytes(
            signing_key_secp256k1.algorithm(),
            &signing_key_secp256k1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signing_key, signing_key_secp256k1);

        let signing_key_secp256r1 = SigningKey::new_secp256r1();
        let re_parsed_signing_key = SigningKey::from_algorithm_and_bytes(
            signing_key_secp256r1.algorithm(),
            &signing_key_secp256r1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signing_key, signing_key_secp256r1);
    }

    #[test]
    fn test_reparsed_signatures_are_equal_to_original() {
        let message = b"test message";

        let signature_ed25519 = SigningKey::new_ed25519().sign(message);
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_ed25519.algorithm(),
            &signature_ed25519.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_ed25519);

        let signature_secp256k1 = SigningKey::new_secp256k1().sign(message);
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_secp256k1.algorithm(),
            &signature_secp256k1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_secp256k1);

        let signature_secp256r1 = SigningKey::new_secp256r1().sign(message);
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_secp256r1.algorithm(),
            &signature_secp256r1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_secp256r1);
    }

    #[test]
    fn test_verifying_key_from_string_ed25519() {
        let original_key: VerifyingKey =
            SigningKey::Ed25519(Box::new(Ed25519SigningKey::new(OsRng))).into();
        let encoded = engine.encode(original_key.to_bytes());

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_ok());

        let decoded_key = result.unwrap();
        assert_eq!(decoded_key.to_bytes(), original_key.to_bytes());
    }

    #[test]
    fn test_verifying_key_from_string_secp256k1() {
        let original_key: VerifyingKey =
            SigningKey::Secp256k1(Secp256k1SigningKey::new(&mut OsRng)).into();
        let encoded = engine.encode(original_key.to_bytes());

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_ok());

        let decoded_key = result.unwrap();
        assert_eq!(decoded_key.to_bytes(), original_key.to_bytes());
    }

    #[test]
    fn test_verifying_key_from_string_invalid_length() {
        let invalid_bytes: [u8; 31] = [1; 31];
        let encoded = engine.encode(invalid_bytes);

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_err());
    }
}
