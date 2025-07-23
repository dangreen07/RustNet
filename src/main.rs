use chrono::prelude::*;
use hex::encode;
use secp256k1::SecretKey;
use sha2::{Digest, Sha256};
use stellar_net::wallet::{SignableTransaction, Transaction, TransactionParticipant, Wallet};

const NUM_ZERO_BYTES: usize = 2;

struct HashableBlock {
    previous_hash: [u8; 32],
    transactions: Vec<Transaction>,
    timestamp: DateTime<Utc>,
    nonce: u64,
}

impl HashableBlock {
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
}

struct Block {
    hashable_block: HashableBlock,
    current_hash: [u8; 32],
}

impl Block {
    fn encode(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&self.hashable_block.encode());
        buffer.extend_from_slice(&self.current_hash);
        return buffer;
    }
}

fn main() {
    let wallet = Wallet::new("dog apple bear tablecloth".to_string());
    println!("Wallet: {wallet:?}");
    let private_key = SecretKey::from_byte_array(wallet.private_key).unwrap();
    let myself = TransactionParticipant::new(wallet.public_key, 50);
    // Creating a new coin
    let signable_transaction = SignableTransaction::new(vec![], vec![myself], 0.02);
    let transaction = Transaction::new(signable_transaction, &private_key);
    println!("Transaction: {transaction:?}");
    // Creating the new block
    let mut hashable_block = HashableBlock {
        previous_hash: [0u8; 32],
        transactions: vec![transaction],
        timestamp: Utc::now(),
        nonce: 0,
    };
    // Mining the block
    let check_against = [0u8; NUM_ZERO_BYTES];
    let mut current_hash = [0u8; 32];
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
    let first_block = Block {
        hashable_block: hashable_block,
        current_hash: current_hash,
    };
}
