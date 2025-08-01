//! The graphical user interface (GUI) for the RustNet application.
//!
//! This module, built with the `iced` framework, provides the user with a visual
//! interface for managing their wallet, interacting with the network, and
//! monitoring the blockchain. It defines the application's state, messages,
//! and the view logic for each screen.

use bip39::{Language, Mnemonic};
use copypasta::{ClipboardContext, ClipboardProvider};
use futures::channel::mpsc;
use hex::{decode, encode};
use iced::{
    Alignment::Center,
    Background, Border, Color,
    Length::{self, Fill},
    Padding, Renderer, Subscription, Task, Theme, alignment, time,
    widget::{Button, Container, Text, button, column, container, row, stack, text, text_input},
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::time::{Duration, Instant};

use crate::blockchain::Storage;
use crate::networking::{full_node_network_worker, wallet_network_worker};
use crate::wallet::Wallet;

/// Defines the operational mode of the application.
///
/// This enum allows the user to select whether they want to run a simple
/// wallet, a full node that syncs the blockchain, or a miner that also
/// participates in creating new blocks.
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
enum AppMode {
    Wallet,
    Node,
    Miner,
}

/// A structure for serializing and deserializing the application's configuration.
///
/// This is used to save and load user settings, including the selected app mode,
/// wallet keys, and a list of discovered peers, to and from `config.json`.
#[derive(Serialize, Deserialize)]
struct ConfigData {
    app_mode: AppMode,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    discovered_peers: Vec<String>,
}

/// State dedicated to the wallet-setup flow (shows passphrase + copy feedback).
#[derive(Default)]
struct WalletSetupState {
    /// Generated 24-word passphrase shown to the user during wallet creation.
    passphrase: String,
    /// When `Some`, the timestamp when "Copied!" overlay started.
    copy_feedback: Option<Instant>,
    /// When `Some`, the timestamp when "Copy failed" overlay started.
    copy_failed_feedback: Option<Instant>,
}

/// State dedicated to the “All Peers” screen.
#[derive(Default)]
struct AllPeersState {
    /// Known/validated peers.
    peers: Vec<String>,
    /// The node's own external multiaddress (if known).
    self_addr: Option<String>,
    /// The value currently typed in the “Add peer” input field.
    input_value: String,
}

/// The main state for the entire GUI application.
///
/// This struct holds all the data necessary to render the user interface,
/// including the current screen, wallet information, peer lists, and handles
/// for communicating with the networking layer.
pub struct State {
    wallet: Option<Wallet>,
    selected_mode: Option<AppMode>,
    current_screen: Screen,
    wallet_setup: WalletSetupState,
    all_peers: AllPeersState,
    import_passphrase: String,
    /// Peers loaded from configuration that must be validated on startup before
    /// being persisted again. These are dialed once the networking subsystem
    /// exposes its sender, and only peers that successfully connect will be
    /// added back to `all_peers.peers`.
    boot_peers: Vec<String>,
    network_tx: Option<mpsc::Sender<Message>>,
    blockchain: Storage,
}

impl Default for State {
    fn default() -> Self {
        let chain = Storage::new("rust_net_chain".to_string());

        let mut state = State {
            wallet: None,
            selected_mode: None,
            current_screen: Screen::NoWallet,
            wallet_setup: WalletSetupState {
                passphrase: "".to_string(),
                copy_feedback: None,
                copy_failed_feedback: None,
            },
            all_peers: AllPeersState::default(),
            import_passphrase: "".to_string(),
            boot_peers: Vec::new(),
            network_tx: None,
            blockchain: chain,
        };

        state.read_config();

        // Debug: print the current blockchain to console for inspection.
        state.blockchain.print_chain();

        state
    }
}

/// An enum representing the different screens in the application.
///
/// This is used to control which view is currently displayed to the user.
#[derive(Debug, Clone, Copy)]
enum Screen {
    NoWallet,
    WalletCreated,
    ImportWallet,
    SelectOption,
    WalletInfo,
    NodeSync,
    MinerMonitoring,
    AllPeers,
}

/// An enum of all possible messages that can be triggered by user interactions
/// or asynchronous events.
///
/// These messages are processed by the `update` function to modify the application's
/// state. This is the primary way that the GUI becomes interactive.
#[derive(Debug, Clone)]
pub enum Message {
    CreateWallet,
    CopyPassphrase,
    CopyFailed,
    HideCopyFeedback,
    Tick,
    ConfirmPassphraseStored,
    WalletMode,
    NodeMode,
    MinerMode,
    NoPeers,
    TextInputChanged(String),
    SubmitButtonPressed,
    NewPeer(String),
    SelfAddress(String),
    PeerValidated(String),
    NetworkSender(mpsc::Sender<Message>),
    ImportPassphraseChanged(String),
    ImportWallet,
    GoToImportWallet,
    GotoMain,
    GoToWalletInfo,
    GoToNodeSync,
    GoToMinerMonitoring,
    GoToAllPeers,
}

impl State {
    /// Renders the sidebar navigation menu.
    fn sidebar(&self) -> Container<Message> {
        let mut buttons = column![].spacing(10);

        if let Some(mode) = self.selected_mode {
            let wallet_button = button(
                container(text("Wallet Info"))
                    .width(Length::Fill)
                    .align_x(alignment::Horizontal::Center),
            )
            .on_press(Message::GoToWalletInfo)
            .width(Length::Fill);
            buttons = buttons.push(wallet_button);

            if matches!(mode, AppMode::Node | AppMode::Miner) {
                let node_button = button(
                    container(text("Node Sync"))
                        .width(Length::Fill)
                        .align_x(alignment::Horizontal::Center),
                )
                .on_press(Message::GoToNodeSync)
                .width(Length::Fill);
                buttons = buttons.push(node_button);
            }

            if matches!(mode, AppMode::Miner) {
                let miner_button = button(
                    container(text("Miner Monitoring"))
                        .width(Length::Fill)
                        .align_x(alignment::Horizontal::Center),
                )
                .on_press(Message::GoToMinerMonitoring)
                .width(Length::Fill);
                buttons = buttons.push(miner_button);
            }

            let peers_button = button(
                container(text("All Peers"))
                    .width(Length::Fill)
                    .align_x(alignment::Horizontal::Center),
            )
            .on_press(Message::GoToAllPeers)
            .width(Length::Fill);
            buttons = buttons.push(peers_button);
        }

        container(buttons).padding(15).width(Length::Fixed(200.0))
    }

    /// Renders the main view of the application based on the current state.
    ///
    /// This is the top-level rendering function that delegates to other functions
    /// based on the `current_screen`.
    pub fn view(&self) -> Container<Message> {
        let content = match self.current_screen {
            Screen::NoWallet => {
                // The buttons
                let create_wallet = button("Create Wallet").on_press(Message::CreateWallet);
                let import_wallet = button("Import Wallet").on_press(Message::GoToImportWallet);

                // The layout
                let buttons_row = row![create_wallet, import_wallet].spacing(10);
                let interface = container(column![buttons_row])
                    .center_x(Fill)
                    .center_y(Fill);

                interface
            }
            Screen::WalletCreated => {
                // Show the passphrase to the user
                let instructions = text(
                    "Copy down this 24 word passphrase as a backup to get into your wallet later",
                )
                .width(Fill)
                .align_x(Center);

                let passphrase: Text<Theme, Renderer> = text(&self.wallet_setup.passphrase)
                    .wrapping(text::Wrapping::Word)
                    .width(Fill);

                // Style the button to look like text
                let passphrase_button = Button::new(passphrase)
                    .on_press(Message::CopyPassphrase)
                    .style(|theme, _status| button::Style {
                        background: None,
                        border: iced::Border::default(),
                        shadow: iced::Shadow::default(),
                        text_color: theme.palette().text,
                    });

                // Create a stack with the passphrase button and overlay the copy feedback
                let mut passphrase_stack = stack![passphrase_button];

                // Add copy feedback overlay if active
                if let Some(copy_time) = self.wallet_setup.copy_feedback {
                    if copy_time.elapsed() < Duration::from_secs(2) {
                        let feedback =
                            container(text("Copied!").size(14).color(iced::Color::WHITE))
                                .style(|_theme| container::Style {
                                    background: Some(iced::Background::Color(
                                        iced::Color::from_rgba(0.2, 0.2, 0.2, 0.9),
                                    )),
                                    text_color: Some(iced::Color::WHITE),
                                    border: iced::Border {
                                        radius: 6.0.into(),
                                        ..Default::default()
                                    },
                                    shadow: iced::Shadow {
                                        color: iced::Color::BLACK,
                                        offset: iced::Vector::new(0.0, 2.0),
                                        blur_radius: 4.0,
                                    },
                                    ..Default::default()
                                })
                                .padding(8)
                                .center_x(Fill)
                                .center_y(Fill);

                        passphrase_stack = passphrase_stack.push(feedback);
                    }
                }

                if let Some(copy_time) = self.wallet_setup.copy_failed_feedback {
                    if copy_time.elapsed() < Duration::from_secs(2) {
                        let feedback =
                            container(text("Copy failed").size(14).color(iced::Color::WHITE))
                                .style(|_theme| container::Style {
                                    background: Some(iced::Background::Color(
                                        iced::Color::from_rgba(0.8, 0.2, 0.2, 0.9),
                                    )),
                                    text_color: Some(iced::Color::WHITE),
                                    border: iced::Border {
                                        radius: 6.0.into(),
                                        ..Default::default()
                                    },
                                    shadow: iced::Shadow {
                                        color: iced::Color::BLACK,
                                        offset: iced::Vector::new(0.0, 2.0),
                                        blur_radius: 4.0,
                                    },
                                    ..Default::default()
                                })
                                .padding(8)
                                .center_x(Fill)
                                .center_y(Fill);

                        passphrase_stack = passphrase_stack.push(feedback);
                    }
                }

                let passphrase_row = row![passphrase_stack].padding(20);

                let confirm_copy_button =
                    button("I confirm I have copied and stored the passphrase")
                        .on_press(Message::ConfirmPassphraseStored);

                let confirm_copy_button = column![confirm_copy_button].width(Fill).align_x(Center);

                let main_column = column![instructions, passphrase_row, confirm_copy_button]
                    .spacing(5)
                    .max_width(800);

                let interface = container(main_column)
                    .center(Fill)
                    .padding(Padding::new(10.))
                    .align_x(Center);

                interface
            }
            Screen::ImportWallet => {
                let instructions = text("Enter your 24-word passphrase").width(Fill).align_x(Center);

                let passphrase_input = text_input("Enter your passphrase", &self.import_passphrase)
                    .on_input(|value| Message::ImportPassphraseChanged(value))
                    .width(Fill);

                let import_button = button("Import Wallet").on_press(Message::ImportWallet);

                let interface = container(column![instructions, passphrase_input, import_button]
                    .spacing(5)
                    .max_width(800))
                    .center(Fill)
                    .padding(Padding::new(10.))
                    .align_x(Center);

                interface
            }
            Screen::SelectOption => {
                let pick_text = text("What mode do you want to be in?")
                    .width(Fill)
                    .align_x(Center);

                let wallet_only = button("Wallet Only").on_press(Message::WalletMode);

                let node_only = button("Wallet & Node").on_press(Message::NodeMode);

                let all_options = button("Miner, Node & Wallet").on_press(Message::MinerMode);

                let interface = container(
                    column![
                        pick_text,
                        row![wallet_only, node_only, all_options].spacing(10.)
                    ]
                    .spacing(5.)
                    .width(Fill)
                    .align_x(Center),
                )
                .center(Fill)
                .padding(Padding::new(10.));

                interface
            }
            Screen::WalletInfo => {
                let title = text("Wallet Info").size(50);
                let mut content = column![title];

                let coins_label = text("Funds: ").size(30);
                let coins_value = if let Some(wallet) = &self.wallet {
                    let bal = self.blockchain.balance(wallet.public_key);
                    format!("{bal:.2}")
                } else {
                    "0".to_string()
                };
                let coins = text(coins_value).size(30);
                content = content.push(row![coins_label, coins]);

                let send = button("Send");
                if let Some(wallet) = &self.wallet {
                    let public_address = text_input("", &encode(wallet.public_key)).style(
                        |theme: &Theme, _status| text_input::Style {
                            background: Background::Color(Color::TRANSPARENT),
                            border: Border::default(),
                            icon: Color::TRANSPARENT,
                            placeholder: theme.palette().text,
                            value: theme.palette().text,
                            selection: theme.palette().primary,
                        },
                    );
                    content = content.push(public_address);
                }
                content = content.push(send);

                let interface = container(content.spacing(5)).padding(15);
                interface
            }
            Screen::NodeSync => {
                let title = text("Node Sync").size(50);

                let block_height_text = text("Block Height: ").size(30);
                let height = self.blockchain.get_best_height();
                let height = match height {
                    Some(height) => height.to_string(),
                    None => "No blocks found".to_string(),
                };
                let block_height = text(height).size(30);
                let block_row = row![block_height_text, block_height];

                let interface = container(column![title, block_row].spacing(5)).padding(15);
                interface
            }
            Screen::MinerMonitoring => {
                let title = text("Miners Overview").size(50);
                let interface = container(column![title]).padding(15);
                interface
            }
            Screen::AllPeers => {
                let title = text("All Peers").size(50);

                // Show our own address if available
                let mut content = column![title];
                if let Some(addr) = &self.all_peers.self_addr {
                    content = content.push(text(format!("Your address: {addr}")));
                }

                // Bind the current input value so the field reflects user edits
                let new_peer_input = text_input(
                    "Enter the Peer's Multi-Address",
                    &self.all_peers.input_value,
                )
                .on_input(|value| Message::TextInputChanged(value));

                let new_peer_button = button("Add New Peer").on_press(Message::SubmitButtonPressed);

                let mut peers_list = column![];

                for addr in &self.all_peers.peers {
                    peers_list = peers_list.push(text_input("", &addr).style(
                        |theme: &Theme, _status| text_input::Style {
                            background: Background::Color(Color::TRANSPARENT),
                            border: Border::default(),
                            icon: Color::TRANSPARENT,
                            placeholder: theme.palette().text,
                            value: theme.palette().text,
                            selection: theme.palette().primary,
                        },
                    ));
                }

                content = content
                    .push(new_peer_input)
                    .push(new_peer_button)
                    .push(peers_list)
                    .height(Fill)
                    .spacing(5);

                let content = column![content];

                let interface = container(content.spacing(5)).padding(15);
                interface
            }
        };

        if self.selected_mode.is_some()
            && !matches!(
                self.current_screen,
                Screen::NoWallet | Screen::WalletCreated | Screen::ImportWallet | Screen::SelectOption
            )
        {
            container(row![self.sidebar(), content])
        } else {
            content
        }
    }

    /// Handles all incoming messages and updates the application state accordingly.
    ///
    /// This function is the heart of the application's logic, processing user
    /// input and other events to drive state changes. It can also return
    /// a `Task` to perform asynchronous operations.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::CreateWallet => {
                let mut rng = bip39::rand::thread_rng();
                let m = Mnemonic::generate_in_with(&mut rng, Language::English, 24).unwrap();
                let passphrase = m.to_string();
                self.wallet_setup.passphrase = passphrase.clone();
                let wallet = Wallet::new(passphrase);
                self.wallet = Some(wallet);

                self.current_screen = Screen::WalletCreated;
            }
            Message::ImportPassphraseChanged(value) => {
                self.import_passphrase = value;
            }
            Message::GoToImportWallet => {
                self.current_screen = Screen::ImportWallet;
            }
            Message::ImportWallet => {
                if !self.import_passphrase.trim().is_empty() {
                    let passphrase = self.import_passphrase.clone();
                    let wallet = Wallet::new(passphrase);
                    self.wallet = Some(wallet);
                    self.import_passphrase.clear();
                    self.current_screen = Screen::SelectOption;
                }
            }
            Message::CopyPassphrase => {
                if let Ok(mut ctx) = ClipboardContext::new() {
                    if ctx
                        .set_contents(self.wallet_setup.passphrase.to_owned())
                        .is_ok()
                    {
                        self.wallet_setup.copy_feedback = Some(Instant::now());
                    } else {
                        return Task::perform(async {}, |_| Message::CopyFailed);
                    }
                } else {
                    return Task::perform(async {}, |_| Message::CopyFailed);
                }

                // Set up a task to hide the feedback after 2 seconds
                return Task::perform(
                    async {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    },
                    |_| Message::HideCopyFeedback,
                );
            }
            Message::CopyFailed => {
                self.wallet_setup.copy_failed_feedback = Some(Instant::now());
                // Set up a task to hide the feedback after 2 seconds
                return Task::perform(
                    async {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    },
                    |_| Message::HideCopyFeedback,
                );
            }
            Message::HideCopyFeedback => {
                self.wallet_setup.copy_feedback = None;
                self.wallet_setup.copy_failed_feedback = None;
            }
            Message::Tick => {
                // Check if we need to hide the copy feedback
                if let Some(copy_time) = self.wallet_setup.copy_feedback {
                    if copy_time.elapsed() >= Duration::from_secs(2) {
                        self.wallet_setup.copy_feedback = None;
                    }
                }
            }
            Message::ConfirmPassphraseStored => {
                self.current_screen = Screen::SelectOption;
            }
            Message::WalletMode => {
                self.current_screen = Screen::WalletInfo;
                self.selected_mode = Some(AppMode::Wallet);
                self.save_config();
            }
            Message::NodeMode => {
                self.current_screen = Screen::NodeSync;
                self.selected_mode = Some(AppMode::Node);
                self.save_config();
            }
            Message::MinerMode => {
                self.current_screen = Screen::MinerMonitoring;
                self.selected_mode = Some(AppMode::Miner);
                self.save_config();
            }
            Message::NoPeers => {
                self.current_screen = Screen::AllPeers;
            }
            Message::TextInputChanged(value) => {
                self.all_peers.input_value = value;
            }
            Message::SubmitButtonPressed => {
                if !self.all_peers.input_value.trim().is_empty() {
                    let input_value = self.all_peers.input_value.clone();
                    self.all_peers.input_value.clear();
                    return Task::done(Message::NewPeer(input_value));
                }
            }
            Message::NewPeer(addr) => {
                // Forward the new peer address to the networking task (if the
                // networking task has already exposed its sender).
                if let Some(tx) = &mut self.network_tx {
                    let _ = tx.try_send(Message::NewPeer(addr.clone()));
                }
            }
            Message::PeerValidated(addr) => {
                // Extract peer id component (string after last "/p2p/") to
                // deduplicate peers regardless of the address/port they were
                // seen on.
                let peer_id_part = addr.rsplit_once("/p2p/").map(|(_, id)| id);

                let duplicate = match peer_id_part {
                    Some(id) => self.all_peers.peers.iter().any(|existing| {
                        existing.rsplit_once("/p2p/").map(|(_, eid)| eid) == Some(id)
                    }),
                    None => self.all_peers.peers.contains(&addr),
                };

                if !duplicate {
                    self.all_peers.peers.push(addr);
                    self.save_config();
                }
            }
            Message::SelfAddress(addr) => {
                self.all_peers.self_addr = Some(addr);
            }
            Message::NetworkSender(sender) => {
                // Store the networking sender for subsequent use.
                self.network_tx = Some(sender.clone());

                // Validate peers loaded from previous sessions. Dial each of
                // them; successful connections will trigger `PeerValidated`,
                // which will add them back to the main peers list and persist
                // them. Peers that fail to connect will be discarded.
                if !self.boot_peers.is_empty() {
                    if let Some(tx) = &mut self.network_tx {
                        for addr in self.boot_peers.iter().cloned() {
                            let _ = tx.try_send(Message::NewPeer(addr));
                        }
                    }

                    // Clear the pending list and persist an empty peers list;
                    // validated peers will be saved again as they succeed.
                    self.boot_peers.clear();
                    self.save_config();
                }
            }
            Message::GotoMain => {
                if let Some(selected_mode) = self.selected_mode {
                    match selected_mode {
                        AppMode::Wallet => self.current_screen = Screen::WalletInfo,
                        AppMode::Node => self.current_screen = Screen::NodeSync,
                        AppMode::Miner => self.current_screen = Screen::MinerMonitoring,
                    }
                }
            }
            Message::GoToWalletInfo => {
                self.current_screen = Screen::WalletInfo;
            }
            Message::GoToNodeSync => {
                self.current_screen = Screen::NodeSync;
            }
            Message::GoToMinerMonitoring => {
                self.current_screen = Screen::MinerMonitoring;
            }
            Message::GoToAllPeers => {
                self.current_screen = Screen::AllPeers;
            }
        }
        if self.all_peers.peers.len() == 0 && self.selected_mode.is_some() {
            return Task::done(Message::NoPeers);
        }
        Task::none()
    }

    /// Saves the current application configuration to `config.json`.
    fn save_config(&self) {
        if let Some(selected_mode) = &self.selected_mode {
            if let Some(wallet) = &self.wallet {
                // Load existing config to preserve fields we don't manage (e.g., node_private_key)
                let mut cfg_value: serde_json::Value = std::fs::read_to_string("config.json")
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_else(|| serde_json::json!({}));

                cfg_value["app_mode"] = serde_json::to_value(selected_mode).unwrap();
                cfg_value["public_key"] = serde_json::Value::String(encode(wallet.public_key));
                cfg_value["private_key"] = serde_json::Value::String(encode(wallet.private_key));
                cfg_value["discovered_peers"] =
                    serde_json::to_value(&self.all_peers.peers).unwrap();

                let serialized = serde_json::to_string(&cfg_value).unwrap();
                let mut config_file = File::create("config.json").unwrap();
                config_file.write_all(serialized.as_bytes()).unwrap();
            }
        }
    }

    /// Reads the application configuration from `config.json` and initializes the state.
    fn read_config(&mut self) {
        let config_file = File::open("config.json");
        let mut config_file = match config_file {
            Ok(file) => file,
            Err(_) => return,
        };
        let mut data: Vec<u8> = vec![];
        let _ = config_file.read_to_end(&mut data);
        let data = String::from_utf8(data).unwrap();
        let Ok(config) = serde_json::from_str::<ConfigData>(&data) else { return; };
        self.selected_mode = Some(config.app_mode);
        // Attempt to restore wallet only if both keys are present and valid
        if let (Some(priv_hex), Some(pub_hex)) = (config.private_key.as_ref(), config.public_key.as_ref()) {
            if let (Ok(priv_vec), Ok(pub_vec)) = (decode(priv_hex), decode(pub_hex)) {
                if priv_vec.len() == 32 && pub_vec.len() == 33 {
                    if let (Ok(private_key), Ok(public_key)) = (
                        priv_vec.as_slice().try_into(),
                        pub_vec.as_slice().try_into(),
                    ) {
                        self.wallet = Some(Wallet::from_keys(private_key, public_key));
                    }
                }
            }
        }
        match config.app_mode {
            AppMode::Wallet if self.wallet.is_some() => {
                self.current_screen = Screen::WalletInfo;
            }
            AppMode::Wallet => {
                self.current_screen = Screen::NoWallet;
            }
            AppMode::Node => {
                self.current_screen = Screen::NodeSync;
            }
            AppMode::Miner => {
                self.current_screen = Screen::MinerMonitoring;
            }
        }
        // Defer peer validation until the networking layer is ready. We will
        // attempt to dial each stored peer once we obtain the networking
        // channel; only peers that successfully connect will be re-added and
        // persisted.
        self.boot_peers = config.discovered_peers;
    }

    /// Creates a subscription for timer-based events.
    ///
    /// This is used to create temporary UI effects, like the "Copied!"
    /// feedback message, that disappear after a short duration.
    pub fn time_subscription(&self) -> Subscription<Message> {
        if self.wallet_setup.copy_feedback.is_some() {
            return time::every(Duration::from_millis(100)).map(move |_| Message::Tick);
        }
        Subscription::none()
    }

    /// Creates a subscription to the networking worker.
    ///
    /// This function is what connects the GUI to the `libp2p` networking layer.
    /// It starts the appropriate network worker based on the selected `AppMode`
    /// and listens for `Message`s produced by it.
    pub fn networking_subscription(&self) -> Subscription<Message> {
        if matches!(self.selected_mode, Some(AppMode::Node | AppMode::Miner)) {
            Subscription::run(full_node_network_worker)
        } else {
            Subscription::run(wallet_network_worker)
        }
    }
}
