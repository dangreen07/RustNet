use libp2p::multiaddr::Protocol;
use std::net::IpAddr;
use std::time::Duration;

use crate::gui::Message;
use futures::{SinkExt, Stream, StreamExt, channel::mpsc};
use iced::stream;
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder, identify,
    kad::{self, store::MemoryStore},
    ping,
    swarm::{NetworkBehaviour, SwarmEvent},
};

fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.octets()[0] == 169 && v4.octets()[1] == 254) // link-local 169.254/16
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.segments()[0] & 0xff00 == 0xfe00) // link-local fe80::/10 etc.
        }
    }
}

enum MyBehaviourEvent {
    Kademlia,
    Identify,
    Ping,
}

// Implement `From` for each behaviour's event type to convert them
// into our custom `MyBehaviourEvent`.
impl From<kad::Event> for MyBehaviourEvent {
    fn from(_event: kad::Event) -> Self {
        MyBehaviourEvent::Kademlia
    }
}

impl From<identify::Event> for MyBehaviourEvent {
    fn from(_event: identify::Event) -> Self {
        MyBehaviourEvent::Identify
    }
}

impl From<ping::Event> for MyBehaviourEvent {
    fn from(_event: ping::Event) -> Self {
        MyBehaviourEvent::Ping
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

pub fn network_worker() -> impl Stream<Item = Message> {
    stream::channel(100, |mut output| async move {
        // Create channel that external components can use to talk to the
        // networking task.
        let (sender, receiver) = mpsc::channel::<Message>(100);

        // Notify GUI with the sender so it can forward commands without relying on globals
        output
            .send(Message::NetworkSender(sender.clone()))
            .await
            .ok();

        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                Default::default(),
                (libp2p::tls::Config::new, libp2p::noise::Config::new),
                libp2p::yamux::Config::default,
            )
            .unwrap()
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
                        "/rustnet/0.1.0".to_string(), // Standard identify protocol version
                        local_key_pair.public(),      // Your local public key
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
            .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
            .unwrap();

        let mut swarm = swarm.fuse();
        let mut receiver = receiver.fuse();

        loop {
            futures::select! {
                swarm_event = swarm.select_next_some() => {
                    match swarm_event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Now listening on {address}");

                            // Forward only public addresses to GUI for display
                            let mut protocols = address.iter();
                            if let Some(p) = protocols.next() {
                                match p {
                                    Protocol::Ip4(ip4) => {
                                        if is_public_ip(&IpAddr::V4(ip4)) {
                                            output.send(Message::SelfAddress(address.to_string())).await.ok();
                                        }
                                    }
                                    Protocol::Ip6(ip6) => {
                                        if is_public_ip(&IpAddr::V6(ip6)) {
                                            output.send(Message::SelfAddress(address.to_string())).await.ok();
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            println!("Connection established with peer {peer_id}");

                            // Determine the remote multi-address that the connection was
                            // established on (handles both dialer and listener cases).
                            let remote_addr = match &endpoint {
                                libp2p::core::ConnectedPoint::Dialer { address, .. } => address.clone(),
                                libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr.clone(),
                            };

                            // Ensure the multiaddr includes the peer id component so it can be
                            // parsed directly by callers expecting `/p2p/<peerId>` to be present.
                            let mut addr_with_peer = remote_addr.clone();
                            if !addr_with_peer.iter().any(|p| matches!(p, Protocol::P2p(_))) {
                                addr_with_peer.push(Protocol::P2p(peer_id.into()));
                            }

                            // Inform the GUI that this peer has been successfully validated.
                            output
                                .send(Message::PeerValidated(addr_with_peer.to_string()))
                                .await
                                .ok();
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            eprintln!("Failed to dial peer {peer_id:?}: {error}");
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            println!("Connection closed with peer {peer_id:?}");
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
                                        Err(_) => {
                                            println!("Failed to convert entered address to Multiaddr!");
                                            break;
                                        },
                                    };
                                    let dial = swarm.get_mut().dial(addr);
                                    if let Err(e) = dial {
                                        eprintln!("Dial error: {e}");
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
