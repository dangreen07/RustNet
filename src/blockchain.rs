use chrono::{DateTime, Utc};
use hex::encode;
use sha2::{Digest, Sha256};

use crate::wallet::{SignableTransaction, Transaction};
use once_cell::sync::OnceCell;

const HASH_TARGET: [u8; 32] = [
    0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

#[derive(Debug)]
struct HashableBlock {
    hashed_transactions: Option<[u8; 32]>,
    previous_hash: [u8; 32],
    transactions: Vec<Transaction>,
    timestamp: DateTime<Utc>,
    nonce: u64,
}

impl HashableBlock {
    fn new(
        previous_hash: [u8; 32],
        transactions: Vec<Transaction>,
        timestamp: DateTime<Utc>,
    ) -> HashableBlock {
        HashableBlock {
            hashed_transactions: None,
            previous_hash,
            transactions,
            timestamp,
            nonce: 0,
        }
    }

    fn hash_transactions(&mut self) -> [u8; 32] {
        let mut transactions_buffer: Vec<u8> = vec![];
        for transaction in &self.transactions {
            transactions_buffer.extend_from_slice(&transaction.encode());
        }
        let mut hashed_transactions = [0u8; 32];
        let hashed_transactions_generic = Sha256::digest(transactions_buffer);
        hashed_transactions.copy_from_slice(&hashed_transactions_generic);
        self.hashed_transactions = Some(hashed_transactions);
        return hashed_transactions;
    }

    fn create_hashable(&mut self) -> Vec<u8> {
        let mut hashable: Vec<u8> = vec![];
        hashable.extend_from_slice(&self.previous_hash);
        if let Some(hashed_transactions) = &self.hashed_transactions {
            hashable.extend_from_slice(hashed_transactions);
        } else {
            hashable.extend(self.hash_transactions());
        }
        let timestamp = self.timestamp.timestamp();
        let timestamp: [u8; 8] = timestamp.to_le_bytes();
        hashable.extend_from_slice(&timestamp);
        let nonce: [u8; 8] = self.nonce.to_le_bytes();
        hashable.extend_from_slice(&nonce);
        return hashable;
    }

    fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&self.previous_hash);
        let mut transactions_buffer: Vec<u8> = vec![];
        for transaction in &self.transactions {
            transactions_buffer.extend_from_slice(&transaction.encode());
        }
        let transactions_size: u64 = transactions_buffer.len().try_into().unwrap();
        let transactions_size: [u8; 8] = transactions_size.to_le_bytes();
        buffer.extend_from_slice(&transactions_size);
        buffer.extend_from_slice(&transactions_buffer);
        let timestamp = self.timestamp.timestamp();
        let timestamp: [u8; 8] = timestamp.to_le_bytes();
        buffer.extend_from_slice(&timestamp);
        let nonce: [u8; 8] = self.nonce.to_le_bytes();
        buffer.extend_from_slice(&nonce);
        return buffer;
    }

    fn decode(data: &Vec<u8>) -> HashableBlock {
        let mut current_index = 0;
        let previous_hash: [u8; 32] = data[current_index..(current_index + 32)]
            .try_into()
            .unwrap();
        current_index += 32;
        let transactions_size: [u8; 8] =
            data[current_index..(current_index + 8)].try_into().unwrap();
        let transactions_size: usize = u64::from_le_bytes(transactions_size).try_into().unwrap();
        current_index += 8;
        let mut transactions: Vec<Transaction> = vec![];
        while current_index < transactions_size {
            let id: [u8; 32] = data[current_index..(current_index + 32)]
                .try_into()
                .unwrap();
            current_index += 32;
            let (signable_transaction, index_update) =
                SignableTransaction::decode(&data[current_index..].to_vec());
            current_index += index_update;
            let signature: [u8; 64] = data[current_index..(current_index + 64)]
                .try_into()
                .unwrap();
            current_index += 64;
            let transaction = Transaction {
                id,
                details: signable_transaction,
                signature,
            };
            transactions.push(transaction);
        }
        let timestamp: [u8; 8] = data[current_index..(current_index + 8)].try_into().unwrap();
        let timestamp: i64 = i64::from_le_bytes(timestamp).try_into().unwrap();
        let timestamp = DateTime::from_timestamp(timestamp, 0).unwrap();
        current_index += 8;
        let nonce: [u8; 8] = data[current_index..(current_index + 8)].try_into().unwrap();
        let nonce: u64 = u64::from_le_bytes(nonce).try_into().unwrap();
        return HashableBlock {
            hashed_transactions: None,
            previous_hash,
            transactions,
            timestamp,
            nonce,
        };
    }
}

#[derive(Debug)]
pub struct Block {
    hashable_block: HashableBlock,
    pub current_hash: [u8; 32],
}

impl Block {
    /// Returns the hash of the parent block (the `previous_hash` field).
    #[inline]
    pub fn previous_hash(&self) -> [u8; 32] {
        self.hashable_block.previous_hash
    }

    pub fn mine(
        previous_hash: [u8; 32],
        transactions: Vec<Transaction>,
        timestamp: DateTime<Utc>,
    ) -> Block {
        let mut hashable_block = HashableBlock::new(previous_hash, transactions, timestamp);
        let current_hash;
        loop {
            let encoded_hashable_block = hashable_block.create_hashable();
            let hashed: [u8; 32] = Sha256::digest(encoded_hashable_block).try_into().unwrap();
            if hashed <= HASH_TARGET {
                // Found Hash
                current_hash = hashed;
                break;
            } else {
                hashable_block.nonce += 1;
            }
        }

        Block {
            hashable_block,
            current_hash,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let hashable_bytes = &self.hashable_block.encode();
        let hashable_len: u64 = hashable_bytes.len().try_into().unwrap();
        let hashable_len: [u8; 8] = hashable_len.to_le_bytes();
        buffer.extend_from_slice(&hashable_len);
        buffer.extend_from_slice(hashable_bytes);
        buffer.extend_from_slice(&self.current_hash);
        return buffer;
    }

    pub fn decode(data: &Vec<u8>) -> Block {
        let mut current_index = 0;
        let hashable_len: [u8; 8] = data[current_index..(current_index + 8)].try_into().unwrap();
        let hashable_len: usize = u64::from_le_bytes(hashable_len).try_into().unwrap();
        current_index += 8;
        let hashable_bytes: Vec<u8> = data[current_index..(current_index + hashable_len)]
            .try_into()
            .unwrap();
        let hashable_block = HashableBlock::decode(&hashable_bytes);
        current_index += hashable_len;
        let current_hash: [u8; 32] = data[current_index..(current_index + 32)]
            .try_into()
            .unwrap();
        return Block {
            hashable_block,
            current_hash,
        };
    }
}

/// Persistent blockchain storage that supports forks (multiple competing chains).
///
/// The storage keeps **all** valid blocks indexed by their hash. It tracks the
/// current *best* tip (the head of the longest chain) via two metadata keys:
/// `best_height` and `best_tip`. When a new block is added, its parent must be
/// present. If the new block extends the chain beyond the current best height
/// it becomes the new canonical tip.
pub struct Storage {
    db: sled::Db,
    best_height: u64,
    best_tip: [u8; 32],
}

impl Clone for Storage {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            best_height: self.best_height,
            best_tip: self.best_tip,
        }
    }
}

impl Storage {
    pub fn new(db_name: String) -> Self {
        static DB_CELL: OnceCell<sled::Db> = OnceCell::new();
        let db = DB_CELL.get_or_init(|| sled::open(&db_name).expect("Failed to open sled DB")).clone();

        let best_height = Self::get_best_height_init(&db);
        let best_tip = Self::get_best_tip_init(&db);

        Storage {
            db,
            best_height,
            best_tip,
        }
    }

    /// Returns the current canonical tip hash.
    pub fn best_tip_hash(&self) -> [u8; 32] {
        self.best_tip
    }

    pub fn get_best_height(&self) -> Option<u64> {
        if let Ok(Some(bytes)) = self.db.get("best_height") {
            let arr: [u8; 8] = bytes.as_ref().try_into().unwrap();
            Some(u64::from_le_bytes(arr))
        } else {
            return None;
        }
    }

    fn get_best_height_init(db: & sled::Db) -> u64 {
        if let Ok(Some(bytes)) = db.get("best_height") {
            let arr: [u8; 8] = bytes.as_ref().try_into().unwrap();
            u64::from_le_bytes(arr)
        } else {
            // No blocks yet; leave DB state untouched.
            0
        }
    }

    fn set_best_height(&mut self) {
        let _ = self
            .db
            .insert("best_height", &self.best_height.to_le_bytes());
    }

    fn get_best_tip_init(db: & sled::Db) -> [u8; 32] {
        if let Ok(Some(bytes)) = db.get("best_tip") {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        } else {
            [0u8; 32]
        }
    }

    fn set_best_tip(&self) {
        let _ = self.db.insert("best_tip", &self.best_tip);
    }

    pub fn add_new_block(&mut self, block: Block) {
        let blocks = self.db.open_tree("blocks").unwrap();
        let metadata = self.db.open_tree("block_meta").unwrap(); // stores height for each block

        // Ensure the parent block exists unless this is a genesis block
        let parent_hash = block.previous_hash();
        if parent_hash != [0u8; 32] {
            let parent_key = encode(parent_hash);
            if blocks.get(parent_key).unwrap().is_none() {
                panic!("Parent block not found. Cannot add orphan block.");
            }
        }

        // Determine this block's height
        let new_height = if parent_hash == [0u8; 32] {
            0
        } else {
            let parent_height_bytes = metadata
                .get(encode(parent_hash))
                .unwrap()
                .expect("Missing metadata for parent block");
            let arr: [u8; 8] = parent_height_bytes.as_ref().try_into().unwrap();
            u64::from_le_bytes(arr) + 1
        };

        // Persist block data
        let current_hash_hex = encode(block.current_hash);
        let _ = blocks.insert(current_hash_hex.clone(), block.encode());
        let _ = metadata.insert(current_hash_hex.as_bytes(), &new_height.to_le_bytes());

        // Update best tip if this block makes a longer chain OR this is the
        // first (genesis) block being added.
        if self.best_height == 0 || new_height > self.best_height {
            self.best_height = new_height;
            self.best_tip = block.current_hash;
            self.set_best_height();
            self.set_best_tip();
        }
    }

    /// Calculates the balance for the given compressed public key by walking
    /// the canonical chain (the chain ending at `best_tip`). The balance is
    /// the sum of all outputs directed to the key minus all inputs spent by
    /// the key.
    pub fn balance(&self, pubkey: [u8; 33]) -> f64 {
        let blocks_tree = self.db.open_tree("blocks").unwrap();

        let mut balance: f64 = 0.;

        let mut current_hash = self.best_tip;

        // Walk back to genesis
        loop {
            if current_hash == [0u8; 32] {
                break;
            }

            let key = encode(current_hash);
            let encoded_block = match blocks_tree.get(key).unwrap() {
                Some(v) => v.to_vec(),
                None => break, // corrupted db; bail
            };

            let block = Block::decode(&encoded_block);

            // Process transactions
            for tx in block.hashable_block.transactions.iter() {
                // Outputs
                for part in tx.details.outputs().iter() {
                    if part.public_key() == pubkey {
                        balance += part.amount();
                    }
                }
                // Inputs
                for part in tx.details.inputs().iter() {
                    if part.public_key() == pubkey {
                        balance -= part.amount();
                    }
                }
            }

            // Move to parent
            current_hash = block.previous_hash();
        }

        if balance < 0. { 0. } else { balance as f64 }
    }

    /// Prints the canonical chain from best tip back to genesis for debugging.
    pub fn print_chain(&self) {
        let blocks_tree = self.db.open_tree("blocks").unwrap();

        println!("=== Blockchain (best height: {}) ===", self.best_height);

        let mut current_hash = self.best_tip;
        let mut height = self.best_height as i64;

        while current_hash != [0u8; 32] {
            let hash_hex = encode(current_hash);
            let encoded_block = match blocks_tree.get(&hash_hex).unwrap() {
                Some(v) => v.to_vec(),
                None => {
                    println!("Missing block data for hash {hash_hex}");
                    break;
                }
            };
            let block = Block::decode(&encoded_block);
            let tx_count = block.hashable_block.transactions.len();
            println!("Height {height}: {hash_hex} | txs: {tx_count}");

            current_hash = block.previous_hash();
            height -= 1;
        }

        println!("=== End of chain ===");
    }

    /// Raw, encoded blocks in `[from, to]` (inclusive)
    pub fn blocks_raw_range(&self, from: u64, to: u64) -> Vec<Vec<u8>> {
        let blocks = self.db.open_tree("blocks").unwrap();
        let metadata = self.db.open_tree("block_meta").unwrap();

        let mut out = vec![];
        for item in metadata.iter().flatten() {
            let (hash, height_bytes) = item;
            let height = u64::from_le_bytes(height_bytes.as_ref().try_into().unwrap());
            if (from..=to).contains(&height) {
                if let Some(raw) = blocks.get(&hash).unwrap() {
                    out.push(raw.to_vec());
                }
            }
        }
        // sort so the caller can append sequentially
        out.sort_by_key(|raw| Block::decode(raw).previous_hash()); // deterministic
        out
    }
}
