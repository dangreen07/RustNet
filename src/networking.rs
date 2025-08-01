//! Manages all peer-to-peer networking using `libp2p`.
//!
//! This module is responsible for setting up the `libp2p` swarm, handling
//! peer discovery through Kademlia, and managing request-response cycles
//! for the custom protocol defined in `protocol.rs`. It distinguishes
//! between full nodes and wallet-only nodes and handles the entire lifecycle
//! of network events.

use hex::{decode as hex_decode, encode as hex_encode};
use libp2p::identity::{self, Keypair};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{
     Behaviour as RequestResponse, Config as ReqResConfig, Event as RequestResponseEvent,
     ProtocolSupport, OutboundFailure,
 };
use serde_json::Value;
use std::fs;
use std::net::IpAddr;
use std::time::Duration;

use crate::gui::Message;
use crate::protocol::{PROTO_ID, ProtoCodec, ProtocolMessage, MessageKind};
use crate::blockchain::{Storage, Block};
use libp2p::request_response::Message as ReqResMsg;
use futures::{SinkExt, Stream, StreamExt, channel::mpsc};
use iced::stream;
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder, identify,
    kad::{self, store::MemoryStore},
    ping,
    swarm::{NetworkBehaviour, SwarmEvent},
};

/// Checks if an `IpAddr` is a public, globally-routable address.
///
/// This function is used to filter out private, loopback, and link-local
/// addresses to ensure that the node only advertises addresses that are
/// reachable from the public internet.
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

/// An enum that aggregates events from all the different network behaviours.
///
/// This is a common pattern in `libp2p` to handle events from multiple
/// behaviours in a single `match` statement. Each variant wraps the event
/// type of a specific behaviour (e.g., Kademlia, Identify).
enum MyBehaviourEvent {
    Kademlia(kad::Event),
    Identify(identify::Event),
    Ping,
    ReqRes(RequestResponseEvent<ProtocolMessage, ProtocolMessage>),
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
    fn from(_event: ping::Event) -> Self {
        MyBehaviourEvent::Ping
    }
}

impl From<RequestResponseEvent<ProtocolMessage, ProtocolMessage>> for MyBehaviourEvent {
    fn from(e: RequestResponseEvent<ProtocolMessage, ProtocolMessage>) -> Self {
        MyBehaviourEvent::ReqRes(e)
    }
}

/// The main network behaviour struct for the `libp2p` swarm.
///
/// This struct combines several `libp2p` behaviours into a single logical unit.
/// - `kademlia`: For peer discovery and routing.
/// - `identify`: For exchanging peer information, like addresses and supported protocols.
/// - `ping`: For checking connection liveness.
/// - `req_res`: For handling the custom request-response protocol.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
struct MyBehaviour {
    kademlia: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    req_res: RequestResponse<ProtoCodec>,
}

/// Loads the node's identity keypair from `config.json` or generates a new one.
///
/// A stable identity is crucial for a node's reputation and long-term
/// participation in the network. This function ensures that the node uses
/// the same `Keypair` across restarts, saving it to the configuration file
/// if one doesn't already exist.
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

/// Loads the desired listening port from `config.json`, or returns 0 to let the OS choose.
///
/// Using a stable port helps peers reconnect to this node more reliably.
/// If a port is used, it is saved back to the configuration file for future runs.
fn load_or_generate_listen_port() -> u16 {
    // Try to read the port from config.json; fall back to 0 (let OS choose).
    let cfg_value: Value = fs::read_to_string("config.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| Value::Object(Default::default()));
    if let Some(port) = cfg_value.get("node_listen_port").and_then(|v| v.as_u64()) {
        return port as u16;
    }
    0
}

/// The main asynchronous task that drives all networking operations.
///
/// This function sets up the `libp2p` swarm, initializes all required
/// network behaviours, and enters a continuous loop to process incoming
/// events from the swarm and from the GUI.
///
/// # Arguments
///
/// * `is_full_node` - A boolean indicating whether the node should operate as a
///   full node (participating in routing and block storage) or a wallet-only node.
pub fn network_worker(is_full_node: bool) -> impl Stream<Item = Message> {
    // Ensure a stable identity.
    let id_keys = load_or_generate_identity();
    // Derive our PeerId once so we can avoid dialing ourselves.
    let local_peer_id = PeerId::from(id_keys.public());

    stream::channel(100, move |mut output| async move {
        use std::collections::HashSet;

        let mut dialed_addrs: HashSet<String> = HashSet::new();
        let mut dialed_peers: HashSet<PeerId> = HashSet::new();
        let mut bootstrap_done = false;
        let mut local_ips: HashSet<IpAddr> = HashSet::new();
        let mut tip_requested: HashSet<PeerId> = HashSet::new();
        let mut connected_peers: HashSet<PeerId> = HashSet::new();
        let mut storage = Storage::new("rust_net_chain".to_string());

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
                libp2p::noise::Config::new,
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
                        .with_interval(Duration::from_secs(60));

                let identify = identify::Behaviour::new(identify_cfg);

                // 3. Ping setup (optional, for connection health)
                let ping = ping::Behaviour::new(ping::Config::new());

                let proto_behaviour = {
                    let protocols = std::iter::once((PROTO_ID.to_string(), ProtocolSupport::Full));
                    let cfg = ReqResConfig::default().with_request_timeout(Duration::from_secs(60));
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

        let listen_port = load_or_generate_listen_port();
        let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse().unwrap();
        swarm.listen_on(listen_addr).unwrap();

        let mut swarm = swarm.fuse();
        let mut receiver = receiver.fuse();

        loop {
            futures::select! {
                swarm_event = swarm.select_next_some() => {
                    match swarm_event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Now listening on {address}");
                            // Record our own listening IPs so we don\'t later try to dial them.
                            if let Some(ip) = address.iter().next() {
                                match ip {
                                    Protocol::Ip4(ip4) => {
                                        local_ips.insert(IpAddr::V4(ip4));
                                    }
                                    Protocol::Ip6(ip6) => {
                                        local_ips.insert(IpAddr::V6(ip6));
                                    }
                                    _ => {}
                                }
                            }

                            // Persist the listening TCP port in config.json so we reuse it next time.
                            if let Some(tcp_port) = address.iter().find_map(|p| if let Protocol::Tcp(port) = p { Some(port) } else { None }) {
                                use std::fs;
                                let mut cfg_value: Value = fs::read_to_string("config.json")
                                    .ok()
                                    .and_then(|s| serde_json::from_str(&s).ok())
                                    .unwrap_or_else(|| Value::Object(Default::default()));
                                cfg_value["node_listen_port"] = serde_json::Value::from(tcp_port as u64);
                                if let Ok(serialized) = serde_json::to_string(&cfg_value) {
                                    let _ = fs::write("config.json", serialized);
                                }
                            }

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
                            connected_peers.insert(peer_id);
                            dialed_peers.insert(peer_id);
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
                                // Only add the address to the DHT if **we** dialed the peer.  If the
                                // peer dialed us, `send_back_addr` is just the transient socket the
                                // peer used and is usually not a valid listening address.
                                if matches!(endpoint, libp2p::core::ConnectedPoint::Dialer { .. }) {
                                    behaviour.kademlia.add_address(&peer_id, remote_addr.clone());
                                }
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
                            connected_peers.remove(&peer_id);
                            println!("Connection closed with peer {peer_id:?}");
                        }
                        SwarmEvent::Behaviour(event) => {
                            match event {
                                MyBehaviourEvent::Kademlia(kad_event) => {
                                    // When the routing table is updated with a new peer, attempt to connect.
                                    if let kad::Event::RoutingUpdated { peer, addresses, .. } = kad_event {
                                        if peer != local_peer_id {
                                            // Only attempt to dial this peer once.
                                            if dialed_peers.insert(peer) {
                                                for addr in addresses.iter() {
                                                    // Skip loopback and our own IPs.
                                                    if addr.iter().any(|p| match p {
                                                        Protocol::Ip4(ip4) => ip4.is_loopback() || local_ips.contains(&IpAddr::V4(ip4)),
                                                        Protocol::Ip6(ip6) => ip6.is_loopback() || local_ips.contains(&IpAddr::V6(ip6)),
                                                        _ => false,
                                                    }) {
                                                        continue;
                                                    }

                                                    let mut addr_with_peer = addr.clone();
                                                    if !addr_with_peer.iter().any(|p| matches!(p, Protocol::P2p(_))) {
                                                        addr_with_peer.push(Protocol::P2p(peer.into()));
                                                    }
                                                    let addr_str = addr_with_peer.to_string();
                                                    if dialed_addrs.insert(addr_str.clone()) {
                                                        if let Err(e) = swarm.get_mut().dial(addr_with_peer.clone()) {
                                                            eprintln!("Dial error: {e}");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                MyBehaviourEvent::ReqRes(req_event) => {
                                    match &req_event {
                                        RequestResponseEvent::Message { .. } => {},
                                        RequestResponseEvent::OutboundFailure { peer, error, request_id } => {
                                            eprintln!("ReqRes outbound failure to {:?}: {:?} (id {:?})", peer, error, request_id);
                                            if let OutboundFailure::ConnectionClosed = error {
                                                // Connection closed before we could send. Retry once on next available connection.
                                                tip_requested.remove(peer);
                                                if swarm.get_ref().is_connected(peer) {
                                                    println!("Retrying RequestTip to {:?} on remaining connection", peer);
                                                    swarm.get_mut().behaviour_mut().req_res.send_request(peer, ProtocolMessage::new(MessageKind::RequestTip));
                                                    tip_requested.insert(*peer);
                                                }
                                            }
                                        }
                                        RequestResponseEvent::InboundFailure { peer, error, request_id } => {
                                            eprintln!("ReqRes inbound failure from {:?}: {:?} (id {:?})", peer, error, request_id);
                                        }
                                        RequestResponseEvent::ResponseSent { peer, request_id } => {
                                            println!("Response sent to {:?} id {:?}", peer, request_id);
                                        }
                                    }
                                    // Handle message events
                                    if let RequestResponseEvent::Message { peer, message } = req_event {
                                        println!("Received message from {peer:?}: {message:?}");
                                        match message {
                                            ReqResMsg::Request { request, channel, .. } => {
                                                match request.kind {
                                                    MessageKind::RequestTip => {
                                                        let best_height = storage.get_best_height().unwrap_or(0);
                                                        let tip_hash = storage.best_tip_hash();
                                                        let response = ProtocolMessage::new(MessageKind::RespondTip { best_height, tip_hash });
                                                        let _ = swarm.get_mut().behaviour_mut().req_res.send_response(channel, response);
                                                    }
                                                    MessageKind::RequestBlocks { from_height, to_height } => {
                                                        // Respect hard cap of 10 blocks per response.
                                                        let capped_to = if to_height > from_height + 9 { from_height + 9 } else { to_height };
                                                        println!("Peer requested blocks {}..{} (capped {})", from_height, to_height, capped_to);
                                                        if is_full_node {
                                                            let blocks = storage.blocks_raw_range(from_height, capped_to);
                                                            let response = ProtocolMessage::new(MessageKind::RespondBlocks { blocks });
                                                            let _ = swarm.get_mut().behaviour_mut().req_res.send_response(channel, response);
                                                        } else {
                                                            // Wallet nodes don't provide blocks.
                                                            let response = ProtocolMessage::new(MessageKind::RespondBlocks { blocks: Vec::new() });
                                                            let _ = swarm.get_mut().behaviour_mut().req_res.send_response(channel, response);
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            ReqResMsg::Response { response, .. } => {
                                                match response.kind {
                                                    MessageKind::RespondTip { best_height, tip_hash } => {
                                                        let our_height_opt = storage.get_best_height();
                                                        let our_height = our_height_opt.unwrap_or(0);
                                                        let our_tip = storage.best_tip_hash();

                                                        println!("RespondTip received: peer_height={} our_height={} peer_tip_zero={} our_tip_zero={}", best_height, our_height, tip_hash == [0u8; 32], our_tip == [0u8; 32]);
                                                        let behind = if best_height > our_height {
                                                            true
                                                        } else if best_height == our_height {
                                                            // Same reported height, but we may still be missing the genesis block.
                                                            // If our tip is the zero hash and the peer's tip is non-zero, we are behind.
                                                            our_tip == [0u8; 32] && tip_hash != [0u8; 32]
                                                        } else {
                                                            false
                                                        };

                                                        println!("Behind decision: {}", behind);
                                                        if behind {
                                                            // Determine the starting height: 0 if we have no blocks, otherwise next height.
                                                            let mut from = if our_tip == [0u8; 32] { 0 } else { our_height + 1 };
                                                            while from <= best_height {
                                                                let to = std::cmp::min(from + 9, best_height);
                                                                println!("Requesting blocks {}..{} from {:?}", from, to, peer);
                                                                swarm.get_mut().behaviour_mut().req_res.send_request(&peer, ProtocolMessage::new(MessageKind::RequestBlocks { from_height: from, to_height: to }));
                                                                from = to + 1;
                                                            }
                                                        }
                                                    }
                                                    MessageKind::RespondBlocks { blocks } => {
                                                         println!("Received RespondBlocks containing {} block(s) from {:?}", blocks.len(), peer);

                                                        for raw in blocks {
                                                            let block = Block::decode(&raw);
                                                            storage.add_new_block(block);
                                                        }
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                }
                                MyBehaviourEvent::Identify(identify_event) => {
                                    if let identify::Event::Received { peer_id, .. } = identify_event {
                                        if connected_peers.contains(&peer_id) && tip_requested.insert(peer_id) {
                                            println!("Identify received from {} - sending RequestTip", peer_id);
                                            let behaviour = swarm.get_mut().behaviour_mut();
                                            behaviour.req_res.send_request(&peer_id, ProtocolMessage::new(MessageKind::RequestTip));
                                        }
                                    }
                                }
                                MyBehaviourEvent::Ping => {}
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
                                    // Skip if the address refers to ourselves (contains our peer id).
                                    if peer_multi_addr.contains(&local_peer_id.to_string()) {
                                        println!("Ignoring self-dial attempt: {peer_multi_addr}");
                                        continue;
                                    }
                                    let addr = peer_multi_addr.parse::<Multiaddr>();
                                    let addr = match addr {
                                        Ok(addr) => addr,
                                        Err(_) => {
                                            println!("Failed to convert entered address to Multiaddr!");
                                            break;
                                        },
                                    };
                                                                // Parse peer id from the multiaddr if present so we can dedupe by peer.
                            let maybe_pid = addr.iter().find_map(|p| {
                                if let Protocol::P2p(pid) = p {
                                    Some(pid.clone())
                                } else {
                                    None
                                }
                            });
                            if let Some(pid) = maybe_pid {
                                if !dialed_peers.insert(pid) {
                                    println!("Already dialed peer {pid}, skipping");
                                    continue;
                                }
                            }
                            if dialed_addrs.insert(peer_multi_addr.clone()) {
                                // Skip loopback / self IPs.
                                if addr.iter().any(|p| match p {
                                    Protocol::Ip4(ip4) => ip4.is_loopback() || local_ips.contains(&IpAddr::V4(ip4)),
                                    Protocol::Ip6(ip6) => ip6.is_loopback() || local_ips.contains(&IpAddr::V6(ip6)),
                                    _ => false,
                                }) {
                                    println!("Skipping dial to local/loopback address {addr}");
                                    continue;
                                }
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

/// A wrapper function to start the network worker in full-node mode.
pub fn full_node_network_worker() -> impl Stream<Item = Message> {
    network_worker(true)
}

/// A wrapper function to start the network worker in wallet-only mode.
pub fn wallet_network_worker() -> impl Stream<Item = Message> {
    network_worker(false)
}
