use std::collections::BTreeMap;

use prism_common::transaction::Transaction;

pub struct TxBuffer(BTreeMap<u64, Vec<Transaction>>);

impl TxBuffer {
    pub fn new() -> Self {
        TxBuffer(BTreeMap::new())
    }

    pub fn take_to_range(&mut self, end: u64) -> Vec<Transaction> {
        let keys: Vec<u64> = self.0.range(..=end).map(|(&k, _)| k).collect();
        keys.into_iter().filter_map(|k| self.0.remove(&k)).flatten().collect()
    }

    pub fn take_all(&mut self) -> Vec<Transaction> {
        let txs = self.0.values().flat_map(|txs| txs.iter().cloned()).collect();
        self.0.clear();
        txs
    }

    pub fn contains_pending(&self) -> bool {
        !self.0.is_empty()
    }

    pub fn insert_at_height(&mut self, height: u64, txs: Vec<Transaction>) {
        self.0.entry(height).or_default().extend(txs);
    }
}
