use chrono::{DateTime, Utc};
use hex::encode;
use sha2::{Digest, Sha256};

use crate::wallet::{SignableTransaction, Transaction};

const NUM_ZERO_BYTES: usize = 2;

#[derive(Debug)]
struct HashableBlock {
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
            previous_hash,
            transactions,
            timestamp,
            nonce: 0,
        }
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
    pub fn mine(
        previous_hash: [u8; 32],
        transactions: Vec<Transaction>,
        timestamp: DateTime<Utc>,
    ) -> Block {
        let mut hashable_block = HashableBlock::new(previous_hash, transactions, timestamp);
        let current_hash;
        let check_against = [0u8; NUM_ZERO_BYTES];
        loop {
            let encoded_hashable_block = hashable_block.encode();
            let hashed = Sha256::digest(encoded_hashable_block);
            let mut check_slice = [0u8; NUM_ZERO_BYTES];
            check_slice.copy_from_slice(&hashed[..NUM_ZERO_BYTES]);
            if check_slice == check_against {
                // Found Hash
                let mut full_slice = [0u8; 32];
                full_slice.copy_from_slice(&hashed);
                let hash_hex = encode(full_slice);
                println!("Found Hash: {hash_hex}");
                current_hash = full_slice;
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
