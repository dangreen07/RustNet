// This file is for managing wallets and transactions for a person.

use hex::encode;
use secp256k1::{
    Message, Secp256k1, SecretKey,
    rand::{SeedableRng, rngs::StdRng},
};
use sha2::{Digest, Sha256};
use std::fmt;

pub struct Wallet {
    pub private_key: [u8; 32],
    pub public_key: [u8; 33],
}

impl Wallet {
    pub fn new(pass_phrase: String) -> Wallet {
        let seed_hash = Sha256::digest(pass_phrase);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_hash);
        let mut rng = StdRng::from_seed(seed);

        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);

        let wallet = Wallet::from_keys(secret_key.secret_bytes(), public_key.serialize());

        return wallet;
    }

    pub fn from_keys(private_key: [u8; 32], public_key: [u8; 33]) -> Wallet {
        return Wallet {
            private_key,
            public_key,
        };
    }
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
pub struct TransactionParticipant {
    public_key: [u8; 33],
    amount: u64,
}

impl TransactionParticipant {
    pub fn new(public_key: [u8; 33], amount: u64) -> TransactionParticipant {
        TransactionParticipant { public_key, amount }
    }
}

#[derive(Clone, Debug)]
pub struct SignableTransaction {
    inputs: Vec<TransactionParticipant>,
    outputs: Vec<TransactionParticipant>,
    fee: f64,
}

impl SignableTransaction {
    pub fn new(
        inputs: Vec<TransactionParticipant>,
        outputs: Vec<TransactionParticipant>,
        fee: f64,
    ) -> SignableTransaction {
        SignableTransaction {
            inputs: inputs,
            outputs: outputs,
            fee: fee,
        }
    }

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

    fn decode_participants(
        data: &Vec<u8>,
        current_index: &mut usize,
    ) -> Vec<TransactionParticipant> {
        const PARTICIPANT_SIZE: usize = 33 + 8;
        let size: [u8; 4] = data[*current_index..(*current_index + 4)]
            .try_into()
            .unwrap();
        let size: usize = u32::from_le_bytes(size).try_into().unwrap();
        let num_participants = size / PARTICIPANT_SIZE;
        *current_index += 4;
        let mut participants: Vec<TransactionParticipant> = Vec::with_capacity(num_participants);
        for _ in 0..num_participants {
            let public_key: [u8; 33] = data[*current_index..(*current_index + 33)]
                .try_into()
                .unwrap();
            *current_index += 33;
            let amount: [u8; 8] = data[*current_index..(*current_index + 8)]
                .try_into()
                .unwrap();
            *current_index += 8;
            let amount: u64 = u64::from_le_bytes(amount).try_into().unwrap();
            participants.push(TransactionParticipant::new(public_key, amount));
        }
        return participants;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];

        SignableTransaction::encode_participants(&self.inputs, &mut buffer);
        SignableTransaction::encode_participants(&self.outputs, &mut buffer);

        let fee_bytes: [u8; 8] = self.fee.to_le_bytes();
        buffer.extend_from_slice(&fee_bytes);
        return buffer;
    }

    pub fn decode(data: &Vec<u8>) -> (SignableTransaction, usize) {
        let mut current_index = 0;
        // Input participants
        let inputs = SignableTransaction::decode_participants(data, &mut current_index);
        let outputs = SignableTransaction::decode_participants(data, &mut current_index);
        let fee: [u8; 8] = data[current_index..(current_index + 8)].try_into().unwrap();
        let fee: f64 = f64::from_le_bytes(fee).try_into().unwrap();
        current_index += 8;
        return (
            SignableTransaction::new(inputs, outputs, fee),
            current_index,
        );
    }
}

#[derive(Debug)]
pub struct Transaction {
    pub id: [u8; 32],
    pub details: SignableTransaction,
    pub signature: [u8; 64],
}

impl Transaction {
    pub fn new(signable: SignableTransaction, private_key: &SecretKey) -> Transaction {
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
        return Transaction {
            id: id,
            details: signable,
            signature: signature,
        };
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&self.id);
        buffer.extend_from_slice(&self.details.encode());
        buffer.extend_from_slice(&self.signature);
        return buffer;
    }
}
