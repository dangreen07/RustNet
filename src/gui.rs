use bip39::{Language, Mnemonic};
use copypasta::{ClipboardContext, ClipboardProvider};
use futures::channel::mpsc;
use hex::{decode, encode};
use iced::{
    Alignment::Center,
    Length::Fill,
    Padding, Subscription, Task, time,
    widget::{Button, Container, Text, button, column, container, row, stack, text, text_input},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::prelude::*;
use std::time::{Duration, Instant};

use crate::networking::network_worker;
use crate::wallet::Wallet;

#[derive(Serialize, Deserialize, Clone, Copy)]
enum AppMode {
    Wallet,
    Node,
    Miner,
}

#[derive(Serialize, Deserialize)]
struct ConfigData {
    app_mode: AppMode,
    private_key: String,
    public_key: String,
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

pub struct State {
    wallet: Option<Wallet>,
    selected_mode: Option<AppMode>,
    current_screen: Screen,
    wallet_setup: WalletSetupState,
    all_peers: AllPeersState,
    network_tx: Option<mpsc::Sender<Message>>,
}

impl Default for State {
    fn default() -> Self {
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
            network_tx: None,
        };

        state.read_config();

        state
    }
}

#[derive(Debug, Clone, Copy)]
enum Screen {
    NoWallet,
    WalletCreated,
    SelectOption,
    WalletInfo,
    NodeSync,
    MinerMonitoring,
    AllPeers,
}

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
    GotoMain,
}

impl State {
    pub fn view(&self) -> Container<Message> {
        match self.current_screen {
            Screen::NoWallet => {
                // The buttons
                let create_wallet = button("Create Wallet").on_press(Message::CreateWallet);

                // The layout
                let interface = container(column![create_wallet])
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

                let passphrase = Text::new(&self.wallet_setup.passphrase)
                    .wrapping(text::Wrapping::Word)
                    .width(Fill);

                // Style the button to look like text
                let passphrase_button = Button::new(passphrase)
                    .on_press(Message::CopyPassphrase)
                    .style(|_theme, _status| button::Style {
                        background: None,
                        border: iced::Border::default(),
                        shadow: iced::Shadow::default(),
                        text_color: iced::Color::from_rgb(1.0, 1.0, 1.0),
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
                let interface = container(column![title]).padding(15);
                interface
            }
            Screen::NodeSync => {
                let title = text("Node Sync").size(50);
                let interface = container(column![title]).padding(15);
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
                    peers_list = peers_list.push(text(addr));
                }

                let leave_button = button("Done").on_press(Message::GotoMain);

                content = content
                    .push(new_peer_input)
                    .push(new_peer_button)
                    .push(peers_list)
                    .height(Fill)
                    .spacing(5);

                let content = column![content, column![leave_button].width(Fill).align_x(Center)];

                let interface = container(content.spacing(5)).padding(15);
                interface
            }
        }
    }

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
                if !self.all_peers.peers.contains(&addr) {
                    self.all_peers.peers.push(addr);
                    self.save_config();
                }
            }
            Message::SelfAddress(addr) => {
                self.all_peers.self_addr = Some(addr);
            }
            Message::NetworkSender(sender) => {
                // Store the networking sender for subsequent use
                self.network_tx = Some(sender);
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
        }
        Task::none()
    }

    fn save_config(&self) {
        if let Some(selected_mode) = &self.selected_mode {
            if let Some(wallet) = &self.wallet {
                let private_key = encode(wallet.private_key);
                let public_key = encode(wallet.public_key);
                let config = ConfigData {
                    app_mode: selected_mode.clone(),
                    public_key,
                    private_key,
                    discovered_peers: self.all_peers.peers.clone(),
                };
                let config = json!(config).to_string();
                let mut config_file = File::create("config.json").unwrap();
                config_file.write_all(config.as_bytes()).unwrap();
            }
        }
    }

    fn read_config(&mut self) {
        let config_file = File::open("config.json");
        let mut config_file = match config_file {
            Ok(file) => file,
            Err(_) => return,
        };
        let mut data: Vec<u8> = vec![];
        let _ = config_file.read_to_end(&mut data);
        let data = String::from_utf8(data).unwrap();
        let config = serde_json::from_str::<ConfigData>(&data).unwrap();
        self.selected_mode = Some(config.app_mode);
        let private_key = decode(config.private_key)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let public_key = decode(config.public_key)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        self.wallet = Some(Wallet::from_keys(private_key, public_key));
        match config.app_mode {
            AppMode::Wallet => {
                self.current_screen = Screen::WalletInfo;
            }
            AppMode::Node => {
                self.current_screen = Screen::NodeSync;
            }
            AppMode::Miner => {
                self.current_screen = Screen::MinerMonitoring;
            }
        }
        self.all_peers.peers = config.discovered_peers;
    }

    pub fn time_subscription(&self) -> Subscription<Message> {
        let num_peers = self.all_peers.peers.len();
        if self.wallet_setup.copy_feedback.is_some() {
            return time::every(Duration::from_millis(100)).map(move |_| {
                println!("Peers: {num_peers}");
                return Message::Tick;
            });
        }
        if num_peers == 0 && self.selected_mode.is_some() {
            return time::every(Duration::from_millis(5)).map(move |_| {
                return Message::NoPeers;
            });
        }
        Subscription::none()
    }

    pub fn networking_subscription(&self) -> Subscription<Message> {
        Subscription::run(network_worker)
    }
}
