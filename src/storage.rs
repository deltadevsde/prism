use redis::{Client, Commands, Connection};
use std::process::Command;
use serde::{Deserialize, Serialize};
use std::{self, fmt::Display, sync::Mutex};
use std::thread::sleep;
use std::time::Duration;

use crate::{
    indexed_merkle_tree::{sha256, Node, ProofVariant},
    utils::parse_json_to_proof,
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum Operation {
    Add,
    Revoke,
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Operation::Add => write!(f, "Add"),
            Operation::Revoke => write!(f, "Revoke"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct ChainEntry {
    pub hash: String,
    pub previous_hash: String,
    pub operation: Operation,
    pub value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Entry {
    pub id: String,
    pub value: Vec<ChainEntry>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DerivedEntry {
    pub id: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingEntry {
    pub id: String,
    pub operation: Operation,
    pub value: String,
}

#[derive(Deserialize, Debug)]
pub struct UpdateEntryJson {
    pub id: String,
    pub signed_message: String,
    pub public_key: String,
}

pub struct RedisConnections {
    pub main_dict: Mutex<Connection>,    // clear text key with hashchain
    pub derived_dict: Mutex<Connection>, // hashed key with last hashchain entry hash
    pub input_order: Mutex<Connection>,  // input order of the hashchain keys
    pub app_state: Mutex<Connection>,    // app state (just epoch counter for now)
    pub merkle_proofs: Mutex<Connection>, // merkle proofs (in the form: epoch_{epochnumber}_{commitment})
    pub commitments: Mutex<Connection>,   // epoch commitments
}

pub trait Database: Send + Sync {
    fn get_keys(&self) -> Vec<String>;
    fn get_derived_keys(&self) -> Vec<String>;
    fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, &str>;
    fn get_derived_value(&self, key: &String) -> Result<String, &str>;
    fn get_derived_keys_in_order(&self) -> Vec<String>;
    fn get_commitment(&self, epoch: &u64) -> Result<String, &str>;
    fn get_proof(&self, id: &String) -> Result<String, &str>;
    fn get_proofs_in_epoch(&self, epoch: &u64) -> Result<Vec<ProofVariant>, &str>;
    fn get_epoch(&self) -> Result<u64, &str>;
    fn get_epoch_operation(&self) -> Result<u64, &str>;
    fn set_epoch(&self, epoch: &u64) -> Result<(), String>;
    fn reset_epoch_operation_counter(&self) -> Result<(), String>;
    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &Vec<ChainEntry>,
    ) -> Result<(), String>;
    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> Result<(), String>;
    fn get_derived_dict_keys_in_order(&self) -> Result<Vec<String>, String>;
    fn get_epochs(&self) -> Result<Vec<u64>, String>;
    fn increment_epoch_operation(&self) -> Result<u64, String>;
    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &String,
        proofs: &String,
    );
    fn add_commitment(&self, epoch: &u64, commitment: &String);
    fn initialize_derived_dict(&self);
    fn flush_database(&self) -> Result<(), Box<dyn std::error::Error>>;
}

impl RedisConnections {
    pub fn new() -> Result<RedisConnections, Box<dyn std::error::Error>> {
        let try_client = Client::open("redis://127.0.0.1/")?;
        let try_connection = try_client.get_connection();

        if try_connection.is_err() {
            // Redis-Server starten, wenn er noch nicht läuft
            println!("Starting redis-server...");
        
            let _child = Command::new("redis-server")
                .spawn()?;
            
            sleep(Duration::from_secs(5));
            println!("Redis-server started.");
        }

        let client = Client::open("redis://127.0.0.1/")?;
        let derived_client = Client::open("redis://127.0.0.1/1")?;
        let input_order = Client::open("redis://127.0.0.1/2")?;
        let app_state = Client::open("redis://127.0.0.1/3")?;
        let merkle_proofs = Client::open("redis://127.0.0.1/4")?;
        let commitments = Client::open("redis://127.0.0.1/5")?;

        Ok(RedisConnections {
            main_dict: Mutex::new(client.get_connection()?),
            derived_dict: Mutex::new(derived_client.get_connection()?),
            input_order: Mutex::new(input_order.get_connection()?),
            app_state: Mutex::new(app_state.get_connection()?),
            merkle_proofs: Mutex::new(merkle_proofs.get_connection()?),
            commitments: Mutex::new(commitments.get_connection()?),
        })
    }

}


impl Database for RedisConnections {
    fn get_keys(&self) -> Vec<String> {
        let mut con = self.main_dict.lock().unwrap();
        let keys: Vec<String> = con.keys("*").unwrap();
        keys
    }

    fn get_derived_keys(&self) -> Vec<String> {
        let mut con = self.derived_dict.lock().unwrap();
        let keys: Vec<String> = con.keys("*").unwrap();
        keys
    }

    fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, &str> {
        let mut con = self.main_dict.lock().unwrap();
        let value: String = match con.get(key) {
            Ok(value) => value,
            Err(_) => return Err("Key not found"),
        };
        match serde_json::from_str(&value) {
            Ok(value) => Ok(value),
            Err(_e) => Err("Internal error parsing value"),
        }
    }

    fn get_derived_value(&self, key: &String) -> Result<String, &str> {
        let mut con = self.derived_dict.lock().unwrap();
        match con.get(key) {
            Ok(value) => Ok(value),
            Err(_) => Err("Key not found"),
        }
    }

    // TODO: bei der get_derived_keys() Funktion ist ein komisches Verhalten aufgefallen, sie gibt die Werte in scheinbar zufälliger Reihenfolge zurück. Fraglich ob es nicht einfach ausreicht,
    // die Werte mit Hilfe der input_order Tabelle zurückzugeben. Das muss nochmal mit @distractedm1nd diskutiert werden :) Dann wäre die obige Funktion auch nicht mehr nötig.
    // Does the order of the keys matter? 
    fn get_derived_keys_in_order(&self) -> Vec<String> {
        let mut input_con = self.input_order.lock().unwrap();
        
        // Die Methode lrange gibt eine Liste der Elemente zwischen zwei Indizes zurück.
        // 0 und -1 bedeuten das erste und das letzte Element, also die gesamte Liste.
        let order: Vec<String> = input_con.lrange("input_order", 0, -1).unwrap();
        
        order
    }

    fn get_commitment(&self, epoch: &u64) -> Result<String, &str> {
        let mut con = self.commitments.lock().unwrap();
        match con.get::<&str, String>(&format!("epoch_{}", epoch)) {
            Ok(value) => {
                let trimmed_value = value.trim_matches('"').to_string();
                Ok(trimmed_value)
            }
            Err(_) => Err("Commitment not found"),
        }
    }

    fn get_proof(&self, id: &String) -> Result<String, &str> {
        let mut con = self.merkle_proofs.lock().unwrap();
        match con.get(id) {
            Ok(value) => Ok(value),
            Err(_) => Err("Proof ID not found"),
        }
    }

    fn get_proofs_in_epoch(&self, epoch: &u64) -> Result<Vec<ProofVariant>, &str> {
        let mut con = self.merkle_proofs.lock().unwrap();
        let mut epoch_proofs: Vec<String> =
            match con.keys::<&String, Vec<String>>(&format!("epoch_{}*", epoch)) {
                Ok(value) => value,
                Err(_) => return Err("Epoch not found"),
            };

        // Sort epoch_proofs by extracting epoch number and number within the epoch
        epoch_proofs.sort_by(|a, b| {
            let a_parts: Vec<&str> = a.split('_').collect();
            let b_parts: Vec<&str> = b.split('_').collect();

            // use second number, for the format: epoch_1_1, epoch_1_2, epoch_1_3 etc. the second number is the number within the epoch
            let a_number: u64 = a_parts[2].parse().unwrap_or(0);
            let b_number: u64 = b_parts[2].parse().unwrap_or(0);

            // Compare first by epoch number, then by number within the epoch
            a_number.cmp(&b_number)
        });

        // Parse the proofs from JSON to ProofVariant
        Ok(epoch_proofs
            .iter()
            .filter_map(|proof| {
                con.get::<&str, String>(proof)
                    .ok()
                    .and_then(|proof_str| parse_json_to_proof(&proof_str).ok())
            })
            .collect())
    }

    fn get_epoch(&self) -> Result<u64, &str> {
        let mut con = self.app_state.lock().unwrap();
        let epoch: u64 = match con.get("epoch") {
            Ok(value) => value,
            Err(_) => return Err("Epoch could not be fetched"),
        };
        Ok(epoch)
    }

    fn get_epoch_operation(&self) -> Result<u64, &str> {
        let mut con = self.app_state.lock().unwrap();
        let epoch_operation: u64 = match con.get("epoch_operation") {
            Ok(value) => value,
            Err(_) => return Err("Epoch operation could not be fetched"),
        };
        Ok(epoch_operation)
    }

    fn set_epoch(&self, epoch: &u64) -> Result<(), String> {
        let mut con = self.app_state.lock().unwrap();
        match con.set::<&str, &u64, String>("epoch", epoch) {
            Ok(_) => Ok(()),
            Err(_) => Err("Epoch could not be set".to_string()),
        }
    }

    fn reset_epoch_operation_counter(&self) -> Result<(), String> {
        let mut con = self.app_state.lock().unwrap();
        match con.set::<&str, &u64, String>("epoch_operation", &0) {
            Ok(_) => Ok(()),
            Err(_) => Err("Epoch operation could not be reset".to_string()),
        }
    }

    fn update_hashchain(
        &self,
        incoming_entry: &IncomingEntry,
        value: &Vec<ChainEntry>,
    ) -> Result<(), String> {
        let mut con = self.main_dict.lock().unwrap();
        let value = serde_json::to_string(&value).unwrap();

        match con.set::<&String, String, String>(&incoming_entry.id, value) {
            Ok(_) => Ok(()),
            Err(_) => Err(format!(
                "Could not update hashchain for key {}",
                incoming_entry.id
            )),
        }
    }

    fn set_derived_entry(
        &self,
        incoming_entry: &IncomingEntry,
        value: &ChainEntry,
        new: bool,
    ) -> Result<(), String> {
        let mut con = self.derived_dict.lock().unwrap();
        let mut input_con = self.input_order.lock().unwrap();
        let hashed_key = sha256(&incoming_entry.id);
        con.set::<&String, &String, String>(&hashed_key, &value.hash)
            .unwrap();
        if new {
            match input_con.rpush::<&'static str, &String, u32>("input_order", &hashed_key) {
                Ok(_) => Ok(()),
                Err(_) => Err(format!("Could not push {} to input order", &hashed_key)),
            }
        } else {
            Ok(())
        }
    }

    fn get_derived_dict_keys_in_order(&self) -> Result<Vec<String>, String> {
        let mut con = self.input_order.lock().unwrap();
        match con.lrange("input_order", 0, -1) {
            Ok(value) => Ok(value),
            Err(_) => Err(format!("Could not fetch input order")),
        }
    }

    fn get_epochs(&self) -> Result<Vec<u64>, String> {
        let mut con = self.commitments.lock().unwrap();

        let epochs: Vec<u64> = match con.keys::<&str, Vec<String>>("*") {
            Ok(value) => value
                .iter()
                .map(|epoch| epoch.replace("epoch_", "").parse::<u64>().unwrap())
                .collect(),
            Err(_) => return Err(format!("Epochs could not be fetched")),
        };
        Ok(epochs)
    }

    fn increment_epoch_operation(&self) -> Result<u64, String> {
        let mut con = self.app_state.lock().unwrap();
        match con.incr::<&'static str, u64, u64>("epoch_operation", 1) {
            Ok(value) => Ok(value),
            Err(_) => Err(format!("Epoch operation could not be incremented")),
        }
    }

    fn add_merkle_proof(
        &self,
        epoch: &u64,
        epoch_operation: &u64,
        commitment: &String,
        proofs: &String,
    ) {
        let mut con = self.merkle_proofs.lock().unwrap();
        let key = format!("epoch_{}_{}_{}", epoch, epoch_operation, commitment);
        match con.set::<&String, &String, String>(&key, &proofs) {
            Ok(_) => debug!("Added merkle proof for key {}", key),
            Err(_) => debug!("Could not add merkle proof for key {}", key),
        };
    }

    fn add_commitment(&self, epoch: &u64, commitment: &String) {
        let mut con = self.commitments.lock().unwrap();
        match con.set::<&String, &String, String>(&format!("epoch_{}", epoch), commitment) {
            Ok(_) => debug!("Added commitment for epoch {}", epoch),
            Err(_) => debug!("Could not add commitment for epoch {}", epoch),
        };
    }

    fn initialize_derived_dict(&self) {
        let mut con = self.derived_dict.lock().unwrap();
        let mut input_con = self.input_order.lock().unwrap();

        let empty_hash = Node::EMPTY_HASH.to_string(); // empty hash is always the first node (H(active=true, label=0^w, value=0^w, next=1^w))
        match con.set::<&String, &String, String>(&empty_hash, &empty_hash) {
            Ok(_) => debug!("Added empty hash to derived dict"),
            Err(_) => debug!("Could not add empty hash to derived dict"),
        }; // set the empty hash as the first node in the derived dict
        match input_con.rpush::<&str, String, u32>("input_order", empty_hash.clone()) {
            Ok(_) => debug!("Added empty hash to input order"),
            Err(_) => debug!("Could not add empty hash to input order"),
        }; // add the empty hash to the input order as first node
    }

    fn flush_database(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut main_conn = self.main_dict.lock().map_err(|e| format!("Failed to lock main_dict: {}", e))?;
        let mut derived_conn = self.derived_dict.lock().map_err(|e| format!("Failed to lock derived_dict: {}", e))?;
        let mut input_order_conn = self.input_order.lock().map_err(|e| format!("Failed to lock input_order: {}", e))?;
        let mut app_state_conn = self.app_state.lock().map_err(|e| format!("Failed to lock app_state: {}", e))?;
        let mut merkle_proof_conn = self.merkle_proofs.lock().map_err(|e| format!("Failed to lock merkle_proofs: {}", e))?;
        let mut commitments_conn = self.commitments.lock().map_err(|e| format!("Failed to lock commitments: {}", e))?;

        redis::cmd("FLUSHALL").query(&mut main_conn)?;
        redis::cmd("FLUSHALL").query(&mut derived_conn)?;
        redis::cmd("FLUSHALL").query(&mut input_order_conn)?;
        redis::cmd("FLUSHALL").query(&mut app_state_conn)?;
        redis::cmd("FLUSHALL").query(&mut merkle_proof_conn)?;
        redis::cmd("FLUSHALL").query(&mut commitments_conn)?;
        Ok(())
    }
}



#[cfg(test)]
mod tests {
    use super::*; 

    // Helper functions

    // set up redis connection and flush database before each test
    fn setup() -> RedisConnections {
        let redis_connections = RedisConnections::new().unwrap();
        redis_connections.flush_database().unwrap();
        redis_connections
    }
    
    // flush database after each test
    fn teardown(redis_connections: &RedisConnections) {
        redis_connections.flush_database().unwrap();
    }

    fn create_mock_chain_entry() -> ChainEntry {
        ChainEntry {
            hash: "test_hash".to_string(),
            previous_hash: "test_previous_hash".to_string(),
            operation: Operation::Add,
            value: "test_value".to_string(),
        }
    }

    fn create_incoming_entry_with_test_value(id: &str) -> IncomingEntry {
        IncomingEntry {
            id: id.to_string(),
            operation: Operation::Add,
            value: "test_value".to_string(),
        }
    }


    // TESTS FOR fn get_keys(&self) -> Vec<String>

    // TODO: In dem Zusammnehang fällt mir jetzt auf, dass wir möglicherweise die get_keys() Funktion umbenennen sollten
    // in get_hashchain_keys() oder so, weil es ja eigentlich nur die Schlüssel der Hashchain zurückgibt. Besser gesagt
    // gibt es auch noch die get_derived_keys() Funktion, die die Schlüssel der derived_dict zurückgibt. Das sind einfach
    // die gehashten Keys. Also möglicherweise: get_keys() und get_hashed_keys() ?!
    // TODO: get_keys() gibt die Schlüssel in umgekehrter Reihenfolge zurück
    #[test]
    fn test_get_keys() {
        // set up redis connection and flush database
        let redis_connections = setup();

        let incoming_entry1 = create_incoming_entry_with_test_value("test_key1");
        let incoming_entry2 = create_incoming_entry_with_test_value("test_key2");
        let incoming_entry3 = create_incoming_entry_with_test_value("test_key3");

        redis_connections.update_hashchain(&incoming_entry1, &vec![create_mock_chain_entry()]).unwrap();
        redis_connections.update_hashchain(&incoming_entry2, &vec![create_mock_chain_entry()]).unwrap();
        redis_connections.update_hashchain(&incoming_entry3, &vec![create_mock_chain_entry()]).unwrap();

        let mut keys = redis_connections.get_keys();
        
        // Überprüfe, ob die zurückgegebenen Schlüssel korrekt sind
        let expected_keys: Vec<String> = vec!["test_key1".to_string(), "test_key2".to_string(), "test_key3".to_string()];
        keys.reverse();
        let returned_keys: Vec<String> = keys;

        assert_eq!(expected_keys, returned_keys);

        teardown(&redis_connections);
    }

    #[test]
    fn test_get_keys_from_empty_dictionary() {
        let redis_connections = setup();

        let keys = redis_connections.get_keys();
        
        let expected_keys: Vec<String> = vec![];
        let returned_keys: Vec<String> = keys;

        assert_eq!(expected_keys, returned_keys);

        teardown(&redis_connections);
    }
    
    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_get_too_much_returned_keys() {
        let redis_connections = setup();

        let incoming_entry1 = create_incoming_entry_with_test_value("test_key_1");
        let incoming_entry2 = create_incoming_entry_with_test_value("test_key_2");
        let incoming_entry3 = create_incoming_entry_with_test_value("test_key_3");

        redis_connections.update_hashchain(&incoming_entry1, &vec![create_mock_chain_entry()]).unwrap();
        redis_connections.update_hashchain(&incoming_entry2, &vec![create_mock_chain_entry()]).unwrap();
        redis_connections.update_hashchain(&incoming_entry3, &vec![create_mock_chain_entry()]).unwrap();

        let mut keys = redis_connections.get_keys();
        
        let too_little_keys: Vec<String> = vec!["test_key1".to_string(), "test_key2".to_string()];
        keys.reverse();
        let returned_keys: Vec<String> = keys;

        assert_eq!(too_little_keys, returned_keys);

        teardown(&redis_connections);
    }
     
    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_get_too_little_returned_keys() {
        let redis_connections = setup();

        let incoming_entry1 = create_incoming_entry_with_test_value("test_key_1");
        let incoming_entry2 = create_incoming_entry_with_test_value("test_key_2");
        let incoming_entry3 = create_incoming_entry_with_test_value("test_key_3");

        redis_connections.update_hashchain(&incoming_entry1, &vec![create_mock_chain_entry()]).unwrap();
        redis_connections.update_hashchain(&incoming_entry2, &vec![create_mock_chain_entry()]).unwrap();
        redis_connections.update_hashchain(&incoming_entry3, &vec![create_mock_chain_entry()]).unwrap();

        let mut keys = redis_connections.get_keys();
        
        let too_little_keys: Vec<String> = vec!["test_key1".to_string(), "test_key2".to_string(), "test_key3".to_string(), "test_key4".to_string()];
        keys.reverse();
        let returned_keys: Vec<String> = keys;

        assert_eq!(too_little_keys, returned_keys);

        teardown(&redis_connections);
    }
    
    //    TESTS FOR fn get_derived_keys(&self) -> Vec<String>

    // siehe obiges TODO
    // TODO: sollte es nicht so sein, dass die update funktion automatisch auch das derived dict weiterführt?
    // TODO: hier ist die Unterscheidung dann auch wieder etwas komisch, weil ich separat die set_derived_dict Funktion nutzen
    // muss, aber selbst wenn das so gewollt ist, ist es kein gutes Design, dass Sie andere Parameter erwartet oder?!
    // Außerdem sollte es ja gar nicht möglich sein, Schlüssel ausschließlich direkt in das derived dict zu schreiben, oder?!
    #[test]
    fn test_get_hashed_keys() {
        let redis_connections = setup();

        let incoming_entry1 = create_incoming_entry_with_test_value("test_key1");
        let incoming_entry2 = create_incoming_entry_with_test_value("test_key2");
        let incoming_entry3 = create_incoming_entry_with_test_value("test_key3");

        redis_connections.set_derived_entry(&incoming_entry1, &create_mock_chain_entry(), true).unwrap();
        redis_connections.set_derived_entry(&incoming_entry2, &create_mock_chain_entry(), true).unwrap();
        redis_connections.set_derived_entry(&incoming_entry3, &create_mock_chain_entry(), true).unwrap();

        let keys = redis_connections.get_derived_keys_in_order();
        
        // Überprüfen, ob die zurückgegebenen Schlüssel korrekt sind
        let expected_keys: Vec<String> = vec![sha256(&"test_key1".to_string()), sha256(&"test_key2".to_string()), sha256(&"test_key3".to_string())];
        // keys.reverse(); HIER MUSS SCHEINBAR NICHT REVERSED WERDEN?!
        let returned_keys: Vec<String> = keys;
        
        assert_eq!(expected_keys, returned_keys);
        
        teardown(&redis_connections); 
    }


    // TESTS FOR fn get_hashchain(&self, key: &String) -> Result<Vec<ChainEntry>, &str>

    #[test]
    fn test_get_hashchain() {
        let redis_connections = setup();

        let incoming_entry = create_incoming_entry_with_test_value("test_key");
        let chain_entry = create_mock_chain_entry();

        redis_connections.update_hashchain(&incoming_entry, &vec![chain_entry.clone()]).unwrap();

        let hashchain = redis_connections.get_hashchain(&incoming_entry.id).unwrap();
        assert_eq!(hashchain[0].hash, chain_entry.hash);
        assert_eq!(hashchain[0].previous_hash, chain_entry.previous_hash);
        assert_eq!(hashchain[0].operation, chain_entry.operation);
        assert_eq!(hashchain[0].value, chain_entry.value);

        teardown(&redis_connections);
    }

    #[test]
    #[should_panic(expected = "Key not found")]
    fn test_try_getting_hashchain_for_missing_key() {
        let redis_connections = setup();

        let incoming_entry = create_incoming_entry_with_test_value("test_key");
        let chain_entry = create_mock_chain_entry();

        redis_connections.update_hashchain(&incoming_entry, &vec![chain_entry.clone()]).unwrap();

        let hashchain = redis_connections.get_hashchain(&"missing_test_key".to_string()).unwrap();
        assert_eq!(hashchain[0].hash, chain_entry.hash);
        assert_eq!(hashchain[0].previous_hash, chain_entry.previous_hash);
        assert_eq!(hashchain[0].operation, chain_entry.operation);
        assert_eq!(hashchain[0].value, chain_entry.value);

        teardown(&redis_connections);
    }

    #[test]
    #[should_panic(expected = "Internal error parsing value")]
    fn test_try_getting_wrong_formatted_hashchain_value() {
        let redis_connections = setup();

        let mut con = redis_connections.main_dict.lock().unwrap();

        #[derive(Serialize, Deserialize, Clone)] 
        struct WrongFormattedChainEntry {
            pub hash_val: String, // instead of just "hash"
            pub previous_hash: String, 
            pub operation: Operation, 
            pub value: String, 
        } 

        let wrong_chain_entry = WrongFormattedChainEntry {
            hash_val: "wrong".to_string(),
            previous_hash: "formatted".to_string(),
            operation: Operation::Add,
            value: "entry".to_string()
        };

        let value = serde_json::to_string(&vec![wrong_chain_entry.clone()]).unwrap();

        con.set::<&String, String, String>(&"key_to_wrong_formatted_chain_entry".to_string(), value).unwrap();

        drop(con); // drop the lock on the connection bc get_hashchain also needs a lock on the connection
        
        let hashchain = redis_connections.get_hashchain(&"key_to_wrong_formatted_chain_entry".to_string()).unwrap();

        assert_eq!(hashchain[0].hash, wrong_chain_entry.clone().hash_val);
        assert_eq!(hashchain[0].previous_hash, wrong_chain_entry.clone().previous_hash);
        assert_eq!(hashchain[0].value, wrong_chain_entry.value);

        teardown(&redis_connections);
    }


    // TESTS FOR fn get_derived_value(&self, key: &String) -> Result<String, &str>
    




    #[test]
    /* 
        TODO: Beim Testschreiben fällt auf, dass hier möglicherweise entweder Dinge nicht richtig benannt wurden, oder nochmal überdacht werden müssen. Die Funktion update_hashchain
        erhält als Parameter einen IncomingEntry und ein Vec<ChainEntry>. Das Vec<ChainEntry> ist der aktuelle Stand der Hashchain, der IncomingEntry ist der neue Eintrag, der hinzugefügt
        werden soll. Ich hätte jetzt im Nachhinein erwartet, dass innerhalb der Funktion die neue Hashchain erstellt wird oder aber einfach nur ein Wert zu einem
        Schlüssel-Werte-Paar erstellt wird. Beides ist aber nicht der Fall, es gibt stattdessen noch eine update_entry() Funktion außerhalb der RedisConnections, die dann die neue Hashchain
        erstellt. Das muss nochmal mit @distractedm1nd diskutiert werden :)
     */
    fn test_update_hashchain() {
        let redis_connections = setup();

        let incoming_entry: IncomingEntry = IncomingEntry { id: "test_key".to_string(), operation: Operation::Add, value: "test_value".to_string() };

        let chain_entries: Vec<ChainEntry> = vec![create_mock_chain_entry()];

        match redis_connections.update_hashchain(&incoming_entry, &chain_entries) {
            Ok(_) => (),
            Err(e) => panic!("Failed to update hashchain: {}", e),
        }

        let hashchain = redis_connections.get_hashchain(&incoming_entry.id).unwrap();
        assert_eq!(hashchain[0].hash, "test_hash");
        assert_eq!(hashchain.len(), 1);

        teardown(&redis_connections);
    }
}


