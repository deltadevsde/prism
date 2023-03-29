use ed25519_dalek::Signature;
use serde::{Serialize, Deserialize};
use std::fmt::Display;

#[derive(Clone, Serialize, Deserialize, Debug)]
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

#[derive(Clone, Serialize, Deserialize, Debug)]
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
    pub public_key: String,
}

/* #[derive(Clone)]
pub struct Dictionary {
    entries: Vec<Entry>,
} 

impl Dictionary {
    pub fn new() -> Dictionary {
        Dictionary {
            entries: Vec::new(),
        }
    }

    fn set_entry(&mut self, value: Entry) {
        self.entries.push(value);
    }

    pub fn add_entry(&mut self, key: &str, value: &str) {
        let mut chain_entry = ChainEntry {
            hash: hex_digest(Algorithm::SHA256, value.as_bytes()),
            previous_hash: "0w".to_string(),
            value: value.to_string(),
        };

        if let Some(entry) = self.entries.iter_mut().find(|e| e.key == key) {
            chain_entry.previous_hash = entry.value.last().unwrap().hash.clone();
            entry.value.push(chain_entry);
        } else {
            self.entries.push(Entry {
                key: key.to_string(),
                value: vec![chain_entry],
            });
        }
    }

    pub fn get_entry(&self, key: String) -> Option<&Vec<ChainEntry>> {
        for entry in &self.entries {
            if entry.key == key {
                return Some(&entry.value);
            }
        }

        None
    }

    pub fn print_chain(&self, key: String) {
        if let Some(chain) = self.get_entry(key.clone()) {
            for entry in chain {
                println!("{}: {}", entry.hash, entry.value);
            }
        } else {
            println!("No entry found for key {}", key);
        }
    }

    pub fn print_all(&self) {
        println!("");
        for entry in &self.entries {
            println!("{}:", entry.key);
            for chain_entry in &entry.value {
                println!("{}: {}, ({})", chain_entry.hash, chain_entry.value, chain_entry.previous_hash);
            }
            println!("");
        }
    }

    // derive a dictionary from the current dictionary
    // the key is the hashed key
    // the value is the last entry in the chain
    pub fn derive_dictionary(&self) -> Self {
        let mut dictionary = Dictionary::new();

        for entry in &self.entries {
            let hash = format!("{}", hex_digest(Algorithm::SHA256, entry.key.as_bytes()));
            dictionary.set_entry(Entry {
                key: hash,
                value: vec![entry.value.last().unwrap().clone()],
            });
        }

        dictionary
    }

}

  */
