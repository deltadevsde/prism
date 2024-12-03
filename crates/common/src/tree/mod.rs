use crate::hashchain::Hashchain;

mod key_directory_tree;
mod proofs;
mod snarkable_tree;

pub use key_directory_tree::*;
pub use proofs::*;
pub use snarkable_tree::*;

/// Enumerates possible responses when fetching tree values
#[derive(Debug)]
pub enum HashchainResponse {
    /// When a hashchain was found, provides the value and its corresponding membership-proof
    Found(Hashchain, MembershipProof),

    /// When no hashchain was found for a specific key, provides the corresponding non-membership-proof
    NotFound(NonMembershipProof),
}

#[cfg(all(test, feature = "test_utils"))]
mod tests {
    use super::*;
    use crate::{
        test_utils::{create_mock_signing_key, TestTreeState},
        tree::HashchainResponse::*,
    };
    use jmt::KeyHash;

    use crate::hasher::Hasher;

    #[test]
    fn test_insert_and_get() {
        let mut tree_state = TestTreeState::default();
        let service = tree_state.register_service("service_1".to_string());
        let account = tree_state.create_account("key_1".to_string(), service.clone());

        let insert_proof = tree_state.insert_account(service.registration.clone()).unwrap();
        assert!(insert_proof.verify().is_ok());

        let insert_proof = tree_state.insert_account(account.clone()).unwrap();
        assert!(insert_proof.verify().is_ok());

        let Found(hashchain, membership_proof) = tree_state.tree.get(account.key_hash).unwrap()
        else {
            panic!("Expected hashchain to be found, but was not found.")
        };

        assert_eq!(hashchain, account.hashchain);
        assert!(membership_proof.verify().is_ok());
    }

    #[test]
    fn test_insert_for_nonexistent_service_fails() {
        let mut tree_state = TestTreeState::default();
        let service = tree_state.register_service("service_1".to_string());
        let account = tree_state.create_account("key_1".to_string(), service.clone());

        let insert_proof = tree_state.insert_account(account.clone());
        assert!(insert_proof.is_err());
    }

    #[test]
    fn test_insert_with_invalid_service_challenge_fails() {
        let mut tree_state = TestTreeState::default();
        let service = tree_state.register_service("service_1".to_string());

        let mut falsified_service = service.clone();
        falsified_service.sk = create_mock_signing_key();

        let account = tree_state.create_account("key_1".to_string(), falsified_service.clone());

        let insert_proof = tree_state.insert_account(service.registration.clone()).unwrap();
        assert!(insert_proof.verify().is_ok());

        let insert_proof = tree_state.insert_account(account.clone());
        assert!(insert_proof.is_err());
    }

    #[test]
    fn test_insert_duplicate_key() {
        let mut tree_state = TestTreeState::default();
        let service = tree_state.register_service("service_1".to_string());
        let account = tree_state.create_account("key_1".to_string(), service.clone());

        let insert_proof = tree_state.insert_account(service.registration.clone()).unwrap();
        assert!(insert_proof.verify().is_ok());

        tree_state.insert_account(account.clone()).unwrap();

        let result = tree_state.insert_account(account.clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_update_existing_key() {
        let mut tree_state = TestTreeState::default();

        let service = tree_state.register_service("service_1".to_string());
        let mut account = tree_state.create_account("key_1".to_string(), service.clone());
        tree_state.insert_account(service.registration.clone()).unwrap();
        tree_state.insert_account(account.clone()).unwrap();

        // Add a new key
        tree_state.add_key_to_account(&mut account).unwrap();

        // Update the account using the correct key index
        let update_proof = tree_state.update_account(account.clone()).unwrap();
        assert!(update_proof.verify().is_ok());

        let get_result = tree_state.tree.get(account.key_hash);
        assert!(matches!(get_result.unwrap(), Found(hc, _) if hc == account.hashchain));
    }

    #[test]
    fn test_update_non_existing_key() {
        let mut tree_state = TestTreeState::default();
        let service = tree_state.register_service("service_1".to_string());
        let account = tree_state.create_account("key_1".to_string(), service.clone());
        tree_state.insert_account(service.registration.clone()).unwrap();

        let result = tree_state.update_account(account);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_non_existing_key() {
        let tree_state = TestTreeState::default();
        let key = KeyHash::with::<Hasher>(b"non_existing_key");

        let result = tree_state.tree.get(key).unwrap();

        let NotFound(non_membership_proof) = result else {
            panic!("Hashchain found for key while it was expected to be missing");
        };

        assert!(non_membership_proof.verify().is_ok());
    }

    #[test]
    fn test_multiple_inserts_and_updates() {
        let mut tree_state = TestTreeState::default();

        let service = tree_state.register_service("service_1".to_string());
        let mut account1 = tree_state.create_account("key_1".to_string(), service.clone());
        let mut account2 = tree_state.create_account("key_2".to_string(), service.clone());

        tree_state.insert_account(service.registration).unwrap();

        tree_state.insert_account(account1.clone()).unwrap();
        tree_state.insert_account(account2.clone()).unwrap();

        // Do insert and update accounts using the correct key indices
        tree_state.add_key_to_account(&mut account1).unwrap();
        tree_state.update_account(account1.clone()).unwrap();

        tree_state.add_unsigned_data_to_account(b"unsigned", &mut account2).unwrap();
        tree_state.update_account(account2.clone()).unwrap();
        tree_state.add_signed_data_to_account(b"signed", &mut account2).unwrap();
        tree_state.update_account(account2.clone()).unwrap();

        let get_result1 = tree_state.tree.get(account1.key_hash);
        let get_result2 = tree_state.tree.get(account2.key_hash);

        assert!(matches!(get_result1.unwrap(), Found(hc, _) if hc == account1.hashchain));
        assert!(matches!(get_result2.unwrap(), Found(hc, _) if hc == account2.hashchain));
    }

    #[test]
    fn test_interleaved_inserts_and_updates() {
        let mut test_tree = TestTreeState::default();

        let service = test_tree.register_service("service_1".to_string());
        let mut account_1 = test_tree.create_account("key_1".to_string(), service.clone());
        let mut account_2 = test_tree.create_account("key_2".to_string(), service.clone());

        test_tree.insert_account(service.registration).unwrap();

        test_tree.insert_account(account_1.clone()).unwrap();

        test_tree.add_key_to_account(&mut account_1).unwrap();
        // Update account_1 using the correct key index
        test_tree.update_account(account_1.clone()).unwrap();

        test_tree.insert_account(account_2.clone()).unwrap();

        test_tree.add_key_to_account(&mut account_2).unwrap();

        // Update account_2 using the correct key index
        let last_proof = test_tree.update_account(account_2.clone()).unwrap();

        let get_result1 = test_tree.tree.get(account_1.key_hash);
        let get_result2 = test_tree.tree.get(account_2.key_hash);

        assert!(matches!(get_result1.unwrap(), Found(hc, _) if hc == account_1.hashchain));
        assert!(matches!(get_result2.unwrap(), Found(hc, _) if hc == account_2.hashchain));
        assert_eq!(
            last_proof.new_root,
            test_tree.tree.get_current_root().unwrap()
        );
    }

    #[test]
    fn test_root_hash_changes() {
        let mut tree_state = TestTreeState::default();
        let service = tree_state.register_service("service_1".to_string());
        let account = tree_state.create_account("key_1".to_string(), service.clone());

        tree_state.insert_account(service.registration).unwrap();

        let root_before = tree_state.tree.get_current_root().unwrap();
        tree_state.insert_account(account).unwrap();
        let root_after = tree_state.tree.get_current_root().unwrap();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_batch_writing() {
        let mut tree_state = TestTreeState::default();
        let service = tree_state.register_service("service_1".to_string());

        let account1 = tree_state.create_account("key_1".to_string(), service.clone());
        let account2 = tree_state.create_account("key_2".to_string(), service.clone());
        tree_state.insert_account(service.registration).unwrap();

        println!("Inserting key1: {:?}", account1.key_hash);
        tree_state.insert_account(account1.clone()).unwrap();

        println!(
            "Tree state after first insert: {:?}",
            tree_state.tree.get_commitment()
        );
        println!(
            "Tree state after first write_batch: {:?}",
            tree_state.tree.get_commitment()
        );

        // Try to get the first value immediately
        let get_result1 = tree_state.tree.get(account1.key_hash);
        println!("Get result for key1 after first write: {:?}", get_result1);

        println!("Inserting key2: {:?}", account2.key_hash);
        tree_state.insert_account(account2.clone()).unwrap();

        println!(
            "Tree state after second insert: {:?}",
            tree_state.tree.get_commitment()
        );
        println!(
            "Tree state after second write_batch: {:?}",
            tree_state.tree.get_commitment()
        );

        // Try to get both values
        let get_result1 = tree_state.tree.get(account1.key_hash);
        let get_result2 = tree_state.tree.get(account2.key_hash);

        println!("Final get result for key1: {:?}", get_result1);
        println!("Final get result for key2: {:?}", get_result2);

        assert!(matches!(get_result1.unwrap(), Found(hc, _) if hc == account1.hashchain));
        assert!(matches!(get_result2.unwrap(), Found(hc, _) if hc == account2.hashchain));
    }
}
