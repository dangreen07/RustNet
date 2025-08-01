//! Manages wallets, transactions, and cryptographic signatures.
//!
//! This module provides the structures and functions necessary for creating
//! and managing user wallets, constructing transactions, and handling the
//! cryptographic operations required to sign and verify them.

use hex::encode;
use secp256k1::{
    Message, Secp256k1, SecretKey,
    rand::{SeedableRng, rngs::StdRng},
};
use sha2::{Digest, Sha256};
use std::fmt;

/// Represents a user's wallet, containing the private and public keys.
///
/// The wallet is the primary means for a user to control their funds. The
/// private key must be kept secret, as it is used to sign transactions,
/// while the public key is used to receive funds and is publicly visible.
pub struct Wallet {
    pub private_key: [u8; 32],
    pub public_key: [u8; 33],
}

impl Wallet {
    /// Creates a new wallet from a given passphrase.
    ///
    /// The passphrase is used to seed a deterministic random number generator,
    /// which then creates a secure private/public keypair.
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

    /// Creates a wallet instance from existing private and public keys.
    ///
    /// This is useful for restoring a wallet from saved keys.
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

/// Represents a participant in a transaction, either as a sender (input) or
/// receiver (output).
///
/// Each participant is defined by their public key and the amount of currency
/// they are sending or receiving.
#[derive(Clone, Copy, Debug)]
pub struct TransactionParticipant {
    public_key: [u8; 33],
    amount: f64,
}

impl TransactionParticipant {
    /// Creates a new transaction participant.
    pub fn new(public_key: [u8; 33], amount: f64) -> TransactionParticipant {
        TransactionParticipant { public_key, amount }
    }

    /// Returns the participant's public key.
    pub fn public_key(&self) -> [u8; 33] {
        self.public_key
    }

    /// Returns the amount associated with this participant.
    pub fn amount(&self) -> f64 {
        self.amount
    }
}

/// Represents the part of a transaction that needs to be signed.
///
/// This includes the inputs, outputs, and transaction fee, but excludes the
/// signature itself. This structure is what is serialized and hashed to create
/// the message that is then signed by the sender's private key.
#[derive(Clone, Debug)]
pub struct SignableTransaction {
    inputs: Vec<TransactionParticipant>,
    outputs: Vec<TransactionParticipant>,
    fee: f64,
}

impl SignableTransaction {
    /// Creates a new signable transaction.
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

    /// Returns a slice of input participants.
    pub fn inputs(&self) -> &[TransactionParticipant] {
        &self.inputs
    }

    /// Returns a slice of output participants.
    pub fn outputs(&self) -> &[TransactionParticipant] {
        &self.outputs
    }

    /// Encodes the list of participants into a byte buffer.
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

    /// Decodes a list of transaction participants from a byte slice.
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
            let amount: f64 = f64::from_le_bytes(amount).try_into().unwrap();
            participants.push(TransactionParticipant::new(public_key, amount));
        }
        return participants;
    }

    /// Encodes the signable transaction into a byte vector for hashing and signing.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];

        SignableTransaction::encode_participants(&self.inputs, &mut buffer);
        SignableTransaction::encode_participants(&self.outputs, &mut buffer);

        let fee_bytes: [u8; 8] = self.fee.to_le_bytes();
        buffer.extend_from_slice(&fee_bytes);
        return buffer;
    }

    /// Decodes a signable transaction from a byte slice and returns the
    /// transaction and the number of bytes consumed.
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

/// Represents a complete, signed transaction.
///
/// A transaction includes a unique ID, the signable details (inputs, outputs, fee),
/// and a cryptographic signature to prove ownership of the funds being spent.
#[derive(Debug)]
pub struct Transaction {
    pub id: [u8; 32],
    pub details: SignableTransaction,
    pub signature: [u8; 64],
}

impl Transaction {
    /// Creates and signs a new transaction.
    ///
    /// This function takes the signable part of a transaction and a private key,
    /// produces a signature, and combines them into a full transaction.
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

    /// Creates a new coinbase transaction.
    ///
    /// Coinbase transactions are special transactions created by miners to collect
    /// block rewards. They have no inputs and are not signed in the traditional sense.
    pub fn new_coin(signable: SignableTransaction) -> Transaction {
        let transaction_bytes = signable.encode();
        let transaction_hashed_generic = Sha256::digest(transaction_bytes.clone());
        let mut transaction_hashed = [0u8; 32];
        transaction_hashed.copy_from_slice(&transaction_hashed_generic);
        let mut id_buffer: Vec<u8> = vec![];
        id_buffer.extend_from_slice(&transaction_bytes);
        let signature = [0u8; 64];
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

    /// Encodes the entire transaction (including signature) into a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&self.id);
        buffer.extend_from_slice(&self.details.encode());
        buffer.extend_from_slice(&self.signature);
        return buffer;
    }
}
