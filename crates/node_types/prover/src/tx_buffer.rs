use prism_common::transaction::Transaction;
use std::collections::BTreeMap;

pub struct TxBuffer {
    transactions: BTreeMap<u64, Vec<Transaction>>,
}

impl TxBuffer {
    pub const fn new() -> Self {
        Self {
            transactions: BTreeMap::new(),
        }
    }

    pub fn take_to_range(&mut self, end: u64) -> Vec<Transaction> {
        let keys: Vec<u64> = self.transactions.range(..=end).map(|(&k, _)| k).collect();

        keys.into_iter().filter_map(|k| self.transactions.remove(&k)).flatten().collect()
    }

    pub fn contains_pending(&self) -> bool {
        !self.transactions.is_empty()
    }

    pub fn insert_at_height(&mut self, height: u64, txs: Vec<Transaction>) {
        self.transactions.entry(height).or_default().extend(txs);
    }
}
