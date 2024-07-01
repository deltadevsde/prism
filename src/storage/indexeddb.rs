use crate::error::DatabaseError;
use crate::storage::Database;
use async_trait::async_trait;
use rexie::{Direction, Index, KeyRange, ObjectStore, Rexie, TransactionMode};
use send_wrapper::SendWrapper;
use serde_wasm_bindgen::{from_value, to_value};

const MAIN_STORE_NAME: &str = "main";
const DERIVED_STORE_NAME: &str = "derived";

#[derive(Debug)]
pub struct IndexedDB {
    db: SendWrapper<Rexie>,
}

impl IndexedDB {
    // pub async fn new(db_name: &str) -> Result<Self, DatabaseError> {
    //     let rexie = Rexie::builder(db_name)
    //         .add_object_store(ObjectStore::new(MAIN_STORE_NAME))
    //         .add_object_store(ObjectStore::new(DERIVED_STORE_NAME))
    //         .build()
    //         .await;
    // }
}

#[async_trait]
impl Database for IndexedDB {
    async fn get_keys(&self) -> Result<Vec<String>, DatabaseError> {
        let keys = self
            .db
            .transaction(&[MAIN_STORE_NAME], TransactionMode::Readonly)
            .get_all_keys()
            .await;
        Ok(keys)
    }

    async fn get_derived_keys(&self) -> Result<Vec<String>, DatabaseError> {
        // Perform the synchronous operations within a synchronous context.
        let keys: Vec<Result<String, serde_wasm_bindgen::Error>> = {
            let txn = self
                .db
                .transaction(&[DERIVED_STORE_NAME], TransactionMode::ReadOnly)?;
            let store = txn.store(DERIVED_STORE_NAME)?;
            let key_values = store
                .get_all(None, None, None, Some(Direction::Next))
                .await?;

            key_values
                .into_iter()
                .map(|(key, _)| from_value::<String>(key))
                .collect()
        };

        // Move only the result data into the async context.
        let keys_result: Result<Vec<String>, serde_wasm_bindgen::Error> =
            keys.into_iter().collect();

        // Handle the result in the async context.
        keys_result.map_err(|e| DatabaseError::from(e))
    }
}

impl From<rexie::Error> for DatabaseError {
    fn from(error: rexie::Error) -> DatabaseError {
        use rexie::Error as E;
        match error {
            e @ E::AsyncChannelError => DatabaseError::OtherError(e.to_string()),
            other => DatabaseError::FatalError(other.to_string()),
        }
    }
}

impl From<serde_wasm_bindgen::Error> for DatabaseError {
    fn from(error: serde_wasm_bindgen::Error) -> DatabaseError {
        DatabaseError::OtherError(format!("Error de/serializing: {error}"))
    }
}
