use iced::Subscription;
use rust_net::gui::State;

// TEMPORARY: create a genesis block with a 50-coin mint to the specified
// address if the chain is empty. Remove after first run to avoid duplicates.
fn maybe_create_genesis() {
    use chrono::Utc;
    use hex::decode;
    use rust_net::blockchain::{Block, Storage};
    use rust_net::wallet::{SignableTransaction, Transaction, TransactionParticipant};

    let mut chain = Storage::new("rust_net_chain".to_string());

    if chain.best_tip_hash() != [0u8; 32] {
        return; // Already initialised
    }

    // 33-byte compressed secp256k1 public key (hex)
    const TARGET_PK_HEX: &str =
        "02e30fa20e9491f87a0a90ffdc8fa1b8f9fca28bf8b8d3c9aad6f5427b27b80dcf";
    let pk_bytes = decode(TARGET_PK_HEX).expect("valid hex");
    let pk: [u8; 33] = pk_bytes.try_into().expect("33 bytes");

    // Coinbase transaction: no inputs, single output 50 coins
    let output = TransactionParticipant::new(pk, 50.);
    let signable = SignableTransaction::new(vec![], vec![output], 0.0);
    let tx = Transaction::new_coin(signable);

    // Mine genesis block
    let genesis = Block::mine([0u8; 32], vec![tx], Utc::now());
    chain.add_new_block(genesis);
    println!("Genesis block created with 50 coins to {TARGET_PK_HEX}");
}

fn main() -> iced::Result {
    maybe_create_genesis();

    iced::application("RustNet Manager", State::update, State::view)
        .subscription(|state| {
            Subscription::batch(vec![
                state.time_subscription(),
                state.networking_subscription(),
            ])
        })
        .run()
}
