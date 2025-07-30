use hex::{decode as hex_decode, encode as hex_encode};
use libp2p::identity::{self, Keypair};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{
    Behaviour as RequestResponse, Config as ReqResConfig, Event as RequestResponseEvent,
    ProtocolSupport,
};
use serde_json::Value;
use std::fs;
use std::net::IpAddr;
use std::time::Duration;

use crate::gui::Message;
use crate::protocol::{PROTO_ID, ProtoCodec, ProtocolMessage};
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
    ReqRes(RequestResponseEvent<ProtocolMessage, ProtocolMessage>),
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

impl From<RequestResponseEvent<ProtocolMessage, ProtocolMessage>> for MyBehaviourEvent {
    fn from(e: RequestResponseEvent<ProtocolMessage, ProtocolMessage>) -> Self {
        MyBehaviourEvent::ReqRes(e)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
struct MyBehaviour {
    kademlia: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    req_res: RequestResponse<ProtoCodec>,
}

fn load_or_generate_identity() -> Keypair {
    // Attempt to read `node_private_key` from config.json
    let mut cfg_value: Value = fs::read_to_string("config.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| Value::Object(Default::default()));

    if let Some(key_hex) = cfg_value.get("node_private_key").and_then(|v| v.as_str()) {
        if let Ok(bytes) = hex_decode(key_hex) {
            if let Ok(kp) = identity::Keypair::from_protobuf_encoding(&bytes) {
                return kp;
            }
        }
    }

    // Generate new keypair and store it in the config.
    let kp = identity::Keypair::generate_ed25519();
    if let Ok(bytes) = kp.to_protobuf_encoding() {
        let key_hex = hex_encode(bytes);
        cfg_value["node_private_key"] = Value::String(key_hex);

        // Write back the updated config (ignore errors – worst case we generate again).
        if let Ok(serialized) = serde_json::to_string(&cfg_value) {
            let _ = fs::write("config.json", serialized);
        }
    }
    kp
}

pub fn network_worker(is_full_node: bool) -> impl Stream<Item = Message> {
    // Ensure a stable identity.
    let id_keys = load_or_generate_identity();

    stream::channel(100, move |mut output| async move {
        use std::collections::HashSet;

        let mut dialed_addrs: HashSet<String> = HashSet::new();
        let mut bootstrap_done = false;

        // Create channel that external components can use to talk to the
        // networking task.
        let (sender, receiver) = mpsc::channel::<Message>(100);

        // Notify GUI with the sender so it can forward commands without relying on globals
        output
            .send(Message::NetworkSender(sender.clone()))
            .await
            .ok();

        let mut swarm = SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                Default::default(),
                (libp2p::tls::Config::new, libp2p::noise::Config::new),
                libp2p::yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(move |local_key_pair| {
                let local_peer_id = PeerId::from(local_key_pair.public());

                // 1. Kademlia setup
                let kademlia = kad::Behaviour::new(
                    local_peer_id,
                    MemoryStore::new(local_peer_id), // `MemoryStore` is simple in-memory storage
                );

                // 2. Identify setup (crucial for Kademlia to work well)
                // Embed the node role in the agent version so peers can distinguish
                // between wallet-only nodes and full nodes.
                let agent_version = if is_full_node {
                    "rustnet-fullnode"
                } else {
                    "rustnet-wallet"
                };

                let identify_cfg =
                    identify::Config::new("/rustnet/0.1.0".to_string(), local_key_pair.public())
                        .with_agent_version(agent_version.to_string())
                        .with_interval(Duration::from_secs(300));

                let identify = identify::Behaviour::new(identify_cfg);

                // 3. Ping setup (optional, for connection health)
                let ping = ping::Behaviour::new(ping::Config::new());

                let proto_behaviour = {
                    let protocols = std::iter::once((PROTO_ID.to_string(), ProtocolSupport::Full));
                    let cfg = ReqResConfig::default();
                    RequestResponse::new(protocols, cfg)
                };

                MyBehaviour {
                    kademlia,
                    identify,
                    ping,
                    req_res: proto_behaviour,
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

                            // Feed address to Kademlia and trigger a bootstrap in order to
                            // discover further peers automatically.
                            {
                                let behaviour = swarm.get_mut().behaviour_mut();
                                behaviour.kademlia.add_address(&peer_id, remote_addr.clone());
                                if !bootstrap_done {
                                    let _ = behaviour.kademlia.bootstrap();
                                    bootstrap_done = true;
                                }
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
                        SwarmEvent::Behaviour(event) => {
                            match event {
                                MyBehaviourEvent::ReqRes(req_event) => {
                                    // TODO: Implement block / balance sync here.
                                    if let RequestResponseEvent::Message { .. } = req_event {
                                        // TODO: Handle actual request / response messages.
                                    }
                                }
                                _ => {}
                            }
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
                                    if dialed_addrs.insert(peer_multi_addr.clone()) {
                                        let dial = swarm.get_mut().dial(addr);
                                        if let Err(e) = dial {
                                            eprintln!("Dial error: {e}");
                                        }
                                    } else {
                                        println!("Already attempted dialing {peer_multi_addr}, skipping");
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

/// Start the networking worker configured as a full node (participates fully
/// in Kademlia routing and advertises itself as a full node).
pub fn full_node_network_worker() -> impl Stream<Item = Message> {
    network_worker(true)
}

/// Start the networking worker configured as a wallet-only node (does not
/// advertise itself as capable of full sync).
pub fn wallet_network_worker() -> impl Stream<Item = Message> {
    network_worker(false)
}
