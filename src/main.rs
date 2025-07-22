use std::fmt;

use chrono::prelude::*;
use hex::encode;
use secp256k1::rand::SeedableRng;
use secp256k1::rand::rngs::StdRng;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

const NUM_ZERO_BYTES: usize = 2;

struct Wallet {
    private_key: [u8; 32],
    public_key: [u8; 33],
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let private_key = encode(self.private_key);
        let public_key = encode(self.public_key);
        f.debug_struct("Wallet")
            .field("private_key", &private_key)
            .field("public_key", &public_key)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
struct TransactionParticipant {
    public_key: [u8; 33],
    amount: u64,
}

#[derive(Clone, Debug)]
struct SignableTransaction {
    inputs: Vec<TransactionParticipant>,
    outputs: Vec<TransactionParticipant>,
    fee: f64,
}

impl SignableTransaction {
    fn encode_participants(vector: &[TransactionParticipant], buffer: &mut Vec<u8>) {
        const DATA_SIZE: usize = 33 + 8 * 4;
        let size: u32 = (vector.len() * DATA_SIZE).try_into().unwrap();
        let size: [u8; 4] = size.to_le_bytes();
        buffer.extend_from_slice(&size);
        let mut vector_buffer: Vec<u8> = Vec::with_capacity(vector.len() * DATA_SIZE);
        for value in vector {
            vector_buffer.extend_from_slice(&value.public_key);
            let amount_bytes: [u8; 8] = value.amount.to_le_bytes();
            vector_buffer.extend_from_slice(&amount_bytes);
        }
        buffer.extend_from_slice(&vector_buffer);
    }

    fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        // Getting the size of the input elements
        SignableTransaction::encode_participants(&self.inputs, &mut buffer);
        SignableTransaction::encode_participants(&self.outputs, &mut buffer);

        let fee_bytes: [u8; 8] = self.fee.to_le_bytes();
        buffer.extend_from_slice(&fee_bytes);
        return buffer;
    }
}

#[derive(Debug)]
struct Transaction {
    id: [u8; 32],
    details: SignableTransaction,
    signature: [u8; 64],
}

impl Transaction {
    fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&self.id);
        buffer.extend_from_slice(&self.details.encode());
        buffer.extend_from_slice(&self.signature);
        return buffer;
    }
}

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

fn create_wallet(passphrase: String) -> Wallet {
    let seed_hash = Sha256::digest(passphrase);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_hash);
    let mut rng = StdRng::from_seed(seed);

    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);

    return Wallet {
        private_key: secret_key.secret_bytes(),
        public_key: public_key.serialize(),
    };
}

fn create_transaction(signable: SignableTransaction, private_key: &SecretKey) -> Transaction {
    let transaction_bytes = signable.encode();
    let transaction_hashed_generic = Sha256::digest(transaction_bytes.clone());
    let mut transaction_hashed = [0u8; 32];
    transaction_hashed.copy_from_slice(&transaction_hashed_generic);
    let secp = Secp256k1::new();
    let signature = secp.sign_ecdsa(Message::from_digest(transaction_hashed), &private_key);
    let signature = signature.serialize_compact();
    let mut id_buffer: Vec<u8> = vec![];
    id_buffer.extend_from_slice(&transaction_bytes);
    id_buffer.extend_from_slice(&signature);
    let id_generic = Sha256::digest(id_buffer);
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_generic);
    let transaction = Transaction {
        id: id,
        details: signable,
        signature: signature,
    };
    return transaction;
}

fn main() {
    let wallet = create_wallet("dog apple bear tablecloth".to_string());
    println!("Wallet: {wallet:?}");
    let private_key = SecretKey::from_byte_array(wallet.private_key).unwrap();
    let myself = TransactionParticipant {
        public_key: wallet.public_key,
        amount: 50,
    };
    // Creating a new coin
    let signable_transaction = SignableTransaction {
        inputs: vec![],
        outputs: vec![myself],
        fee: 0.2,
    };
    let transaction = create_transaction(signable_transaction, &private_key);
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
        let mut full_slice = [0u8; 32];
        full_slice.copy_from_slice(&hashed);
        let hash_hex = encode(full_slice);
        println!("Found Hash: {hash_hex}");
        if check_slice == check_against {
            // Found Hash
            current_hash = full_slice;
            break;
        } else {
            hashable_block.nonce += 1;
        }
    }
    let _ = Block {
        hashable_block: hashable_block,
        current_hash: current_hash,
    };
}
