use std::time::Duration;

use crate::gui::Message;
use futures::Stream;
use futures::StreamExt;
use futures::channel::mpsc;
use iced::stream;
use libp2p::Multiaddr;
use libp2p::{
    PeerId, SwarmBuilder, identify,
    kad::{self, store::MemoryStore},
    ping,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use once_cell::sync::Lazy;
use std::sync::Mutex;

#[derive(Debug)]
enum MyBehaviourEvent {
    Kademlia(kad::Event),
    Identify(identify::Event),
    Ping(ping::Event),
}

// Implement `From` for each behaviour's event type to convert them
// into our custom `MyBehaviourEvent`.
impl From<kad::Event> for MyBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        MyBehaviourEvent::Kademlia(event)
    }
}

impl From<identify::Event> for MyBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        MyBehaviourEvent::Identify(event)
    }
}

impl From<ping::Event> for MyBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        MyBehaviourEvent::Ping(event)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
struct MyBehaviour {
    kademlia: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    // If you use `with_relay_client()`:
    // relay: libp2p::relay::client::Behaviour,
}

static NETWORK_SENDER: Lazy<Mutex<Option<mpsc::Sender<Message>>>> = Lazy::new(|| Mutex::new(None));

/// Stores a clone of the network [`Sender`] so other parts of the application
/// (e.g. the GUI) can forward [`Message`]s to the networking task.
pub fn set_network_sender(sender: mpsc::Sender<Message>) {
    *NETWORK_SENDER.lock().unwrap() = Some(sender);
}

/// Retrieves a cloned handle to the network [`Sender`] if it has already been
/// initialised by [`network_worker`]. Returns `None` otherwise.
pub fn get_network_sender() -> Option<mpsc::Sender<Message>> {
    NETWORK_SENDER.lock().unwrap().clone()
}

pub fn network_worker() -> impl Stream<Item = Message> {
    stream::channel(100, |mut _output| async move {
        // Create channel that external components can use to talk to the
        // networking task.
        let (sender, receiver) = mpsc::channel::<Message>(100);

        // Make the sender globally available.
        set_network_sender(sender);

        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_quic()
            .with_behaviour(|local_key_pair| {
                let local_peer_id = PeerId::from(local_key_pair.public());

                // 1. Kademlia setup
                let kademlia = kad::Behaviour::new(
                    local_peer_id,
                    MemoryStore::new(local_peer_id), // `MemoryStore` is simple in-memory storage
                );

                // 2. Identify setup (crucial for Kademlia to work well)
                // Identify shares your node's public addresses and supported protocols
                let identify = identify::Behaviour::new(
                    identify::Config::new(
                        "/ipfs/0.1.0".to_string(), // Standard identify protocol version
                        local_key_pair.public(),   // Your local public key
                    )
                    .with_interval(Duration::from_secs(300)), // Periodically identify
                );

                // 3. Ping setup (optional, for connection health)
                let ping = ping::Behaviour::new(ping::Config::new());

                MyBehaviour {
                    kademlia,
                    identify,
                    ping,
                }
            })
            .unwrap()
            .build();

        swarm
            .listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())
            .unwrap();

        let mut swarm = swarm.fuse();
        let mut receiver = receiver.fuse();

        loop {
            futures::select! {
                swarm_event = swarm.select_next_some() => {
                    match swarm_event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Now listening on {address}");
                        }
                        _ => {}
                    }
                }

                msg = receiver.next() => {
                    match msg {
                        Some(msg) => {
                            match msg {
                                Message::NewPeer(peer_multi_addr) => {
                                    let addr = peer_multi_addr.parse::<Multiaddr>();
                                    let addr = match addr {
                                        Ok(addr) => addr,
                                        Err(_) => break,
                                    };
                                    let dial = swarm.get_mut().dial(addr);
                                    match dial {
                                        Ok(_) => break,
                                        Err(_) => break
                                    }
                                }
                                _ => {}
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    })
}
