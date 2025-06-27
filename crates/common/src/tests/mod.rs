use prism_keys::SigningKey;

use crate::{account::Account, operation::Operation};

#[test]
fn test_process_register_service_transactions() {
    let service_key = SigningKey::new_ed25519();
    let challenge_key = SigningKey::new_ed25519();

    // happy path - should succeed
    let create_tx = Account::builder()
        .register_service()
        .with_id("Service".to_string())
        .with_key(service_key.verifying_key())
        .requiring_signed_challenge(challenge_key.verifying_key())
        .unwrap()
        .sign(&service_key)
        .unwrap()
        .transaction();

    assert!(Account::default().process_transaction(&create_tx).is_ok());

    // should fail with invalid nonce
    let mut unsigned_invalid_tx = Account::builder()
        .register_service()
        .with_id("Service".to_string())
        .with_key(service_key.verifying_key())
        .requiring_signed_challenge(challenge_key.verifying_key())
        .unwrap()
        .transaction();

    unsigned_invalid_tx.nonce = 1; // has to be 0 for RegisterService
    let invalid_tx = unsigned_invalid_tx.sign(&service_key).unwrap();

    assert!(Account::default().process_transaction(&invalid_tx).is_err());

    // should fail when operation id and transaction id are not equal
    let mut unsigned_invalid_tx = Account::builder()
        .register_service()
        .with_id("Service".to_string())
        .with_key(service_key.verifying_key())
        .requiring_signed_challenge(challenge_key.verifying_key())
        .unwrap()
        .transaction();

    if let Operation::RegisterService { id, .. } = &mut unsigned_invalid_tx.operation {
        *id = "DifferentService".to_string();
    } else {
        panic!("Unexpected operation type");
    }
    let invalid_tx = unsigned_invalid_tx.sign(&service_key).unwrap();

    assert!(Account::default().process_transaction(&invalid_tx).is_err());

    // should fail when transaction is signed with an invalid key
    let invalid_key = SigningKey::new_ed25519();
    let invalid_tx = Account::builder()
        .register_service()
        .with_id("Service".to_string())
        .with_key(service_key.verifying_key())
        .requiring_signed_challenge(challenge_key.verifying_key())
        .unwrap()
        .sign(&invalid_key)
        .unwrap()
        .transaction();

    assert!(Account::default().process_transaction(&invalid_tx).is_err());
}

#[test]
fn test_process_create_account_transactions() {
    let service_key = SigningKey::new_ed25519();
    let acc_key = SigningKey::new_ed25519();

    // happy path - should succeed
    let create_tx = Account::builder()
        .create_account()
        .with_id("Acc".to_string())
        .for_service_with_id("Service".to_string())
        .with_key(acc_key.verifying_key())
        .meeting_signed_challenge(&service_key)
        .unwrap()
        .sign(&acc_key)
        .unwrap()
        .transaction();

    assert!(Account::default().process_transaction(&create_tx).is_ok());

    // should fail with invalid nonce
    let mut unsigned_invalid_tx = Account::builder()
        .create_account()
        .with_id("Acc".to_string())
        .for_service_with_id("Service".to_string())
        .with_key(acc_key.verifying_key())
        .meeting_signed_challenge(&service_key)
        .unwrap()
        .transaction();

    unsigned_invalid_tx.nonce = 1; // has to be 0 for CreateAccount
    let invalid_tx = unsigned_invalid_tx.sign(&acc_key).unwrap();

    assert!(Account::default().process_transaction(&invalid_tx).is_err());

    // should fail when operation id and transaction id are not equal
    let mut unsigned_invalid_tx = Account::builder()
        .create_account()
        .with_id("Acc".to_string())
        .for_service_with_id("Service".to_string())
        .with_key(acc_key.verifying_key())
        .meeting_signed_challenge(&service_key)
        .unwrap()
        .transaction();

    if let Operation::CreateAccount { id, .. } = &mut unsigned_invalid_tx.operation {
        *id = "DifferentAcc".to_string();
    } else {
        panic!("Unexpected operation type");
    }
    let invalid_tx = unsigned_invalid_tx.sign(&acc_key).unwrap();

    assert!(Account::default().process_transaction(&invalid_tx).is_err());

    // should fail when transaction is signed with an invalid key
    let invalid_key = SigningKey::new_ed25519();
    let invalid_tx = Account::builder()
        .create_account()
        .with_id("Acc".to_string())
        .for_service_with_id("Service".to_string())
        .with_key(acc_key.verifying_key())
        .meeting_signed_challenge(&service_key)
        .unwrap()
        .sign(&invalid_key)
        .unwrap()
        .transaction();

    assert!(Account::default().process_transaction(&invalid_tx).is_err());
}
