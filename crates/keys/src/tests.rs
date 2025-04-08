#[cfg(test)]
mod key_tests {
    use ed25519_consensus::SigningKey as Ed25519SigningKey;
    use prism_serde::base64::{FromBase64, ToBase64};
    use rand::rngs::OsRng;
    use std::{env, fs::remove_file};

    use crate::{CryptoAlgorithm, Signature, SigningKey, VerifyingKey};

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

        let verifying_key_eip191 = SigningKey::new_eip191().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_bytes(
            verifying_key_eip191.algorithm(),
            &verifying_key_eip191.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_eip191);

        let verifying_key_cosmos_adr36 = SigningKey::new_cosmos_adr36().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_bytes(
            verifying_key_cosmos_adr36.algorithm(),
            &verifying_key_cosmos_adr36.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_cosmos_adr36);
    }

    #[test]
    fn test_reparsed_der_verifying_keys_are_equal_to_original() {
        // Not implemented for ec25519 / eip191 / cosmos_adr36 - skipping that

        let verifying_key_secp256r1 = SigningKey::new_secp256r1().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_der(
            verifying_key_secp256r1.algorithm(),
            &verifying_key_secp256r1.to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_secp256r1);

        let verifying_key_secp256k1 = SigningKey::new_secp256k1().verifying_key();
        let re_parsed_verifying_key = VerifyingKey::from_algorithm_and_der(
            verifying_key_secp256k1.algorithm(),
            &verifying_key_secp256k1.to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(re_parsed_verifying_key, verifying_key_secp256k1);
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

        let signing_key_eip191 = SigningKey::new_eip191();
        let re_parsed_signing_key = SigningKey::from_algorithm_and_bytes(
            signing_key_eip191.algorithm(),
            &signing_key_eip191.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signing_key, signing_key_eip191);

        let signing_key_cosmos_adr36 = SigningKey::new_cosmos_adr36();
        let re_parsed_signing_key = SigningKey::from_algorithm_and_bytes(
            signing_key_cosmos_adr36.algorithm(),
            &signing_key_cosmos_adr36.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signing_key, signing_key_cosmos_adr36);
    }

    #[test]
    fn test_reparsed_signing_keys_from_pkcs8_files() {
        let temp_dir = env::temp_dir();

        // Ed25519
        let signing_key_ed25519 = SigningKey::new_ed25519();
        let pkcs8_path = temp_dir.join("ed25519.p8");

        signing_key_ed25519.to_pkcs8_pem_file(&pkcs8_path).unwrap();
        let re_parsed_signing_key = SigningKey::from_pkcs8_pem_file(&pkcs8_path).unwrap();

        assert_eq!(re_parsed_signing_key, signing_key_ed25519);
        remove_file(&pkcs8_path).unwrap();

        // Secp256k1
        let signing_key_secp256k1 = SigningKey::new_secp256k1();
        let pkcs8_path = temp_dir.join("secp256k1.p8");

        signing_key_secp256k1.to_pkcs8_pem_file(&pkcs8_path).unwrap();
        let re_parsed_signing_key = SigningKey::from_pkcs8_pem_file(&pkcs8_path).unwrap();

        assert_eq!(re_parsed_signing_key, signing_key_secp256k1);
        remove_file(&pkcs8_path).unwrap();

        // Secp256r1
        let signing_key_secp256r1 = SigningKey::new_secp256r1();
        let pkcs8_path = temp_dir.join("secp256r1.p8");

        signing_key_secp256r1.to_pkcs8_pem_file(&pkcs8_path).unwrap();
        let re_parsed_signing_key = SigningKey::from_pkcs8_pem_file(&pkcs8_path).unwrap();

        assert_eq!(re_parsed_signing_key, signing_key_secp256r1);
        remove_file(&pkcs8_path).unwrap();

        // EIP-191 and Cosmos ADR-36 are using SECP256K1 signing keys and are omitted here
    }

    #[test]
    fn test_reparsed_signatures_are_equal_to_original() {
        let message = b"test message";

        let signature_ed25519 = SigningKey::new_ed25519().sign(message).unwrap();
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_ed25519.algorithm(),
            &signature_ed25519.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_ed25519);

        let signature_secp256k1 = SigningKey::new_secp256k1().sign(message).unwrap();
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_secp256k1.algorithm(),
            &signature_secp256k1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_secp256k1);

        let signature_secp256r1 = SigningKey::new_secp256r1().sign(message).unwrap();
        let re_parsed_signature = Signature::from_algorithm_and_bytes(
            signature_secp256r1.algorithm(),
            &signature_secp256r1.to_bytes(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_secp256r1);

        // EIP-191 and Cosmos ADR-36 are using SECP256K1 signatures and are omitted here
    }

    #[test]
    fn test_reparsed_der_signatures_are_equal_to_original() {
        let message = b"test message";

        let signature_secp256k1 = SigningKey::new_secp256k1().sign(message).unwrap();
        let re_parsed_signature = Signature::from_algorithm_and_der(
            signature_secp256k1.algorithm(),
            &signature_secp256k1.to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_secp256k1);

        let signature_secp256r1 = SigningKey::new_secp256r1().sign(message).unwrap();
        let re_parsed_signature = Signature::from_algorithm_and_der(
            signature_secp256r1.algorithm(),
            &signature_secp256r1.to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(re_parsed_signature, signature_secp256r1);

        // EIP-191 and Cosmos ADR-36 are using SECP256K1 signatures and are omitted here
    }

    #[test]
    fn test_created_signatures_can_be_verified() {
        let message = b"test message";

        for algorithm in CryptoAlgorithm::all() {
            let signing_key = SigningKey::new_with_algorithm(algorithm).unwrap();
            let verifying_key = signing_key.verifying_key();

            // Ensure a signature can be created with the signing key
            let signature = signing_key.sign(message).unwrap();

            // Ensure the signature can be verified with the verifying key
            let result = verifying_key.verify_signature(message, &signature);
            assert!(
                result.is_ok(),
                "Verification failed for algorithm {:?}: {}",
                algorithm,
                result.err().unwrap()
            );

            // Verify that a tampered message fails
            let tampered_message = b"tampered message";
            let result = verifying_key.verify_signature(tampered_message, &signature);
            assert!(
                result.is_err(),
                "Verification of tampered message should fail for algorithm: {:?}",
                algorithm
            );
        }
    }

    #[test]
    fn test_eip191_wallet_signatures_can_be_verified() {
        // ETHEREUM EIP-191 Signatures
        // A hex encoded signature was created using metamask wallet.
        // Its the result of signing the message "Example `personal_sign` message"
        // via EIP-191 (wallet.personal_sign).
        // The wallets address is 0x6be8e4d4df40e11e9d89dfa4b65566100d67bb8c.
        let message = String::from("Example `personal_sign` message");

        // These base64 values were derived from the signature
        // d8471e8cb611f2a1636380bfbf1e0197b10e3a93bf86a9567699feb6fcd070452375828b49930c171836e58df8a93f9a24abb2bc31b1e2165d734fefaef0d90b1c
        // Currently it is required to derive the verifying key from the signature
        // on client side and send both to the server separately.
        // The signature is expeted to arrive without the parity byte.
        // Here, we simulate that the client has acted like described and converted both to base64.
        let verifying_key_base64 = "A+mFEKkNVbIaZN3Bq95WpE2EpMHG+06ZBm985YggAaA3";
        let signature_base64 = "2EcejLYR8qFjY4C/vx4Bl7EOOpO/hqlWdpn+tvzQcEUjdYKLSZMMFxg25Y34qT+aJKuyvDGx4hZdc0/vrvDZCw==";

        // Ensure crypto material from wallet can be parsed in prism
        let verifying_key_bytes = Vec::<u8>::from_base64(verifying_key_base64).unwrap();
        let signature_bytes = Vec::<u8>::from_base64(signature_base64).unwrap();

        let signature =
            Signature::from_algorithm_and_bytes(CryptoAlgorithm::Secp256k1, &signature_bytes)
                .unwrap();
        let verifying_key =
            VerifyingKey::from_algorithm_and_bytes(CryptoAlgorithm::Eip191, &verifying_key_bytes)
                .unwrap();

        // Ensure EIP-191 signature can be verified in prism
        verifying_key.verify_signature(message, &signature).unwrap();
    }

    #[test]
    fn test_cosmos_adr36_wallet_signatures_can_be_verified() {
        // COSMOS ADR-36 Signatures
        // This base64 encoded signature bundle was created using Keplr wallet.
        // Its the result of signing the message "123" via cosmos ADR-36 (keplr.signArbitrary)
        // using a private key that belongs to the public key specified below.
        // The wallets address is cosmos1wk68469sk92ktxhuufrn9xeux3e6fn5kkkzrpj.
        let message = String::from("123");
        let public_key_base64 = "AzInFFk+Ht0PA40u/T0L+3qpPk+EuHBq8mqJr974Asg1";
        let signature_base64 = "jU9Q9lnY5gAO51dpt+8d7FpngPLlV6S9S/YBM9vve2JHTkxfMvQch1+hq9hdAD8XiJ69JFsaNW3zu3bTmCEOvA==";

        // Ensure crypto material from keplr can be parsed in prism
        let public_key_bytes = Vec::<u8>::from_base64(public_key_base64).unwrap();
        let signature_bytes = Vec::<u8>::from_base64(signature_base64).unwrap();

        let verifying_key =
            VerifyingKey::from_algorithm_and_bytes(CryptoAlgorithm::CosmosAdr36, &public_key_bytes)
                .unwrap();
        let signature =
            Signature::from_algorithm_and_bytes(CryptoAlgorithm::Secp256k1, &signature_bytes)
                .unwrap();

        // Ensure keplr signature can be verified in prism
        verifying_key.verify_signature(message, &signature).unwrap();
    }

    #[test]
    fn test_verifying_key_from_string_ed25519() {
        let original_key = SigningKey::Ed25519(Ed25519SigningKey::new(OsRng)).verifying_key();
        let encoded = original_key.to_bytes().to_base64();

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_ok());

        let decoded_key = result.unwrap();
        assert_eq!(decoded_key, original_key);
    }

    #[test]
    fn test_verifying_key_from_string_invalid_length() {
        let invalid_bytes: [u8; 31] = [1; 31];
        let encoded = invalid_bytes.to_base64();

        let result = VerifyingKey::try_from(encoded);
        assert!(result.is_err());
    }
}
