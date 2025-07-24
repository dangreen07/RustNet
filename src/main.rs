use chrono::prelude::*;
use rust_net::{
    blockchain::Block,
    wallet::{SignableTransaction, Transaction, TransactionParticipant, Wallet},
};
use secp256k1::SecretKey;
use sled::{Db, open};

fn main() {
    let wallet = Wallet::new("dog apple bear tablecloth".to_string());
    println!("Wallet: {wallet:?}");
    let private_key = SecretKey::from_byte_array(wallet.private_key).unwrap();
    let myself = TransactionParticipant::new(wallet.public_key, 50);
    // Creating a new coin
    let signable_transaction = SignableTransaction::new(vec![], vec![myself], 0.02);
    let transaction = Transaction::new(signable_transaction, &private_key);
    println!("Transaction: {transaction:?}");
    // Creating the genesis block
    let first_block = Block::mine([0u8; 32], vec![transaction], Utc::now());

    let first_block = Block::decode(&first_block.encode());

    println!("First Block: {first_block:?}");
    // Store the newly mined block in the on-system blockchain
    // let chain: Db = open("rust_net_chain").unwrap();
    // let _ = chain.insert(first_block.current_hash, first_block.encode());

    // let block = chain.get(first_block.current_hash).unwrap().unwrap();

    // println!("Read block data: {block:?}");

    // // Clean up as in testing
    // let _ = chain.remove(first_block.current_hash);
}
