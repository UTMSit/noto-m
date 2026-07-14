use crate::network::{CallSignalType, FriendStatus, InnerPayload, NetworkEvent, UiCommand};
use base64::{engine::general_purpose, Engine as _};
use eframe::egui;
use libp2p::{identity, PeerId};
use sha2::Digest;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SavedProfile {
    pub keypair_protobuf_hex: String,
    pub username: String,
    pub friends: Vec<SavedFriend>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SavedFriend {
    pub peer_id: String,
    pub username: String,
    pub is_pending_approval: Option<bool>,
    pub messages: Vec<ChatMessage>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum ChatMessageContent {
    Text(String),
    File {
        name: String,
        mime: String,
        bytes: Vec<u8>,
    },
    Photo {
        name: String,
        bytes: Vec<u8>,
    },
    Video {
        name: String,
        bytes: Vec<u8>,
    },
    VoiceNote {
        duration: u32,
        bytes: Vec<u8>,
        is_playing: bool,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ChatMessage {
    pub is_ours: bool,
    pub timestamp: String,
    pub content: ChatMessageContent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Idle,
    Dialing,
    Ringing,
    Active { duration_secs: u32, is_muted: bool },
}

#[derive(Debug, Clone)]
pub struct FriendState {
    pub peer_id: PeerId,
    pub username: String,
    pub status: FriendStatus,
    pub is_pending_approval: bool,
    pub messages: Vec<ChatMessage>,
    pub call: CallState,
}

pub enum AppAuthState {
    SelectProfile,
    CreateProfile,
    UnlockProfile,
    Unlocked,
}

pub struct NotoMApp {
    auth_state: AppAuthState,
    password_input: String,
    password_error: Option<String>,

    is_restore_tab: bool,
    backup_input: String,
    exported_backup_code: Option<String>,
    show_export_window: bool,

    available_profiles: Vec<String>,
    selected_profile_name: String,
    new_profile_name_input: String,

    local_peer_id: Option<PeerId>,
    my_addresses: Vec<libp2p::Multiaddr>,
    my_username: String,
    my_keypair_protobuf: Vec<u8>,
    friends: HashMap<PeerId, FriendState>,
    active_friend: Option<PeerId>,

    invite_input: String,
    message_input: String,

    recording_voice_note: bool,
    recorded_secs: u32,

    cmd_tx: Option<mpsc::Sender<UiCommand>>,
    evt_rx: Option<mpsc::Receiver<NetworkEvent>>,
}

impl NotoMApp {
    pub fn new() -> Self {
        let profiles = list_profiles();
        let auth_state = if profiles.is_empty() {
            AppAuthState::CreateProfile
        } else {
            AppAuthState::SelectProfile
        };

        Self {
            auth_state,
            password_input: String::new(),
            password_error: None,
            is_restore_tab: false,
            backup_input: String::new(),
            exported_backup_code: None,
            show_export_window: false,
            available_profiles: profiles,
            selected_profile_name: String::new(),
            new_profile_name_input: String::new(),
            local_peer_id: None,
            my_addresses: Vec::new(),
            my_username: String::new(),
            my_keypair_protobuf: Vec::new(),
            friends: HashMap::new(),
            active_friend: None,
            invite_input: String::new(),
            message_input: String::new(),
            recording_voice_note: false,
            recorded_secs: 0,
            cmd_tx: None,
            evt_rx: None,
        }
    }
}

fn list_profiles() -> Vec<String> {
    let mut profiles = Vec::new();
    if let Ok(entries) = std::fs::read_dir(".") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "dat" {
                    if let Some(file_name) = path.file_stem() {
                        let name_str = file_name.to_string_lossy();
                        if name_str.starts_with("noto_profile_") {
                            let profile_name = name_str["noto_profile_".len()..].to_string();
                            profiles.push(profile_name);
                        }
                    }
                }
            }
        }
    }
    profiles
}

fn get_profile_path(profile_name: &str) -> String {
    format!("noto_profile_{}.dat", profile_name)
}

fn save_profile(
    filepath: &str,
    password: &str,
    keypair_protobuf: &[u8],
    username: &str,
    friends: &HashMap<PeerId, FriendState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let saved_friends = friends
        .iter()
        .map(|(peer_id, state)| SavedFriend {
            peer_id: peer_id.to_string(),
            username: state.username.clone(),
            is_pending_approval: Some(state.is_pending_approval),
            messages: state.messages.clone(),
        })
        .collect::<Vec<_>>();

    let profile = SavedProfile {
        keypair_protobuf_hex: hex::encode(keypair_protobuf),
        username: username.to_string(),
        friends: saved_friends,
    };

    let json_str = serde_json::to_string(&profile)?;

    let mut hasher = sha2::Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes: [u8; 32] = hasher.finalize().into();

    let nonce = [0u8; 16];
    let mut cipher = crate::crypto::CustomCipher::new(&key_bytes, &nonce);
    let encrypted_bytes = cipher.encrypt(json_str.as_bytes());

    std::fs::write(filepath, encrypted_bytes)?;
    Ok(())
}

fn load_profile(
    filepath: &str,
    password: &str,
) -> Result<SavedProfile, Box<dyn std::error::Error>> {
    let encrypted_bytes = std::fs::read(filepath)?;

    let mut hasher = sha2::Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes: [u8; 32] = hasher.finalize().into();

    let nonce = [0u8; 16];
    let mut cipher = crate::crypto::CustomCipher::new(&key_bytes, &nonce);
    let decrypted_bytes = cipher.decrypt(&encrypted_bytes);

    let json_str = String::from_utf8(decrypted_bytes)?;
    let profile: SavedProfile = serde_json::from_str(&json_str)?;
    Ok(profile)
}

pub fn configure_styles(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;

    style.visuals.panel_fill = egui::Color32::from_rgb(20, 24, 30);
    style.visuals.window_fill = egui::Color32::from_rgb(28, 34, 42);
    style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(28, 34, 42);
    style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(36, 44, 54);
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(46, 56, 70);
    style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(64, 78, 96);

    style.visuals.widgets.inactive.rounding = egui::Rounding::same(12.0_f32);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(12.0_f32);
    style.visuals.widgets.active.rounding = egui::Rounding::same(12.0_f32);

    let mut families = std::collections::BTreeMap::new();
    families.insert(egui::TextStyle::Heading, egui::FontId::proportional(22.0));
    families.insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
    families.insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    families.insert(egui::TextStyle::Small, egui::FontId::proportional(11.0));
    style.text_styles = families.into_iter().collect();

    ctx.set_style(style);
}

impl eframe::App for NotoMApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match &self.auth_state {
            AppAuthState::SelectProfile => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.heading("Select Local Account");
                        ui.add_space(10.0);
                        ui.label("Choose an existing profile to unlock, or register a new one.");
                        ui.add_space(20.0);

                        ui.group(|ui| {
                            ui.set_max_width(400.0);
                            for profile_name in &self.available_profiles {
                                if ui
                                    .add(
                                        egui::Button::new(format!(
                                            "Unlock Profile: {}",
                                            profile_name
                                        ))
                                        .min_size(egui::vec2(360.0, 36.0)),
                                    )
                                    .clicked()
                                {
                                    self.selected_profile_name = profile_name.clone();
                                    self.password_error = None;
                                    self.password_input.clear();
                                    self.auth_state = AppAuthState::UnlockProfile;
                                }
                                ui.add_space(6.0);
                            }
                        });

                        ui.add_space(20.0);
                        if ui
                            .add(
                                egui::Button::new("Create New Account")
                                    .min_size(egui::vec2(180.0, 36.0)),
                            )
                            .clicked()
                        {
                            self.auth_state = AppAuthState::CreateProfile;
                            self.password_error = None;
                            self.password_input.clear();
                        }
                    });
                });
                return;
            }
            AppAuthState::CreateProfile => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(60.0);
                        ui.heading("Setup Noto-m Account");
                        ui.add_space(10.0);

                        ui.horizontal(|ui| {
                            ui.add_space(340.0);
                            if ui.selectable_label(!self.is_restore_tab, "Create New Account").clicked() {
                                self.is_restore_tab = false;
                                self.password_error = None;
                            }
                            ui.add_space(10.0);
                            if ui.selectable_label(self.is_restore_tab, "Restore from Backup").clicked() {
                                self.is_restore_tab = true;
                                self.password_error = None;
                            }
                        });
                        ui.add_space(20.0);

                        if !self.is_restore_tab {
                            ui.group(|ui| {
                                ui.set_max_width(380.0);
                                ui.label("Local Profile/Account Name (e.g. Work, Personal):");
                                ui.text_edit_singleline(&mut self.new_profile_name_input);
                                ui.add_space(10.0);
                                ui.label("Display Username:");
                                ui.text_edit_singleline(&mut self.my_username);
                                ui.add_space(10.0);
                                ui.label("Master Password (local encryption):");
                                ui.add(egui::TextEdit::singleline(&mut self.password_input).password(true));
                            });

                            if let Some(err) = &self.password_error {
                                ui.add_space(8.0);
                                ui.colored_label(egui::Color32::from_rgb(230, 80, 80), err);
                            }

                            ui.add_space(20.0);
                            if ui.add(egui::Button::new("Create Profile").min_size(egui::vec2(160.0, 36.0))).clicked() {
                                if self.new_profile_name_input.is_empty() || self.my_username.is_empty() || self.password_input.is_empty() {
                                    self.password_error = Some("All fields must be filled.".to_string());
                                } else {
                                    let sanitized_name = self.new_profile_name_input.trim().replace(" ", "_");
                                    let file_path = get_profile_path(&sanitized_name);
                                    if std::path::Path::new(&file_path).exists() {
                                        self.password_error = Some("A profile with this name already exists.".to_string());
                                    } else {
                                        self.selected_profile_name = sanitized_name;
                                        let keypair = identity::Keypair::generate_ed25519();
                                        let key_bytes = keypair.to_protobuf_encoding().unwrap();
                                        self.my_keypair_protobuf = key_bytes.clone();

                                        let _ = save_profile(
                                            &file_path,
                                            &self.password_input,
                                            &self.my_keypair_protobuf,
                                            &self.my_username,
                                            &self.friends,
                                        );

                                        let (cmd_tx, cmd_rx) = mpsc::channel(100);
                                        let (evt_tx, evt_rx) = mpsc::channel(100);
                                        self.cmd_tx = Some(cmd_tx);
                                        self.evt_rx = Some(evt_rx);

                                        let key_clone = self.my_keypair_protobuf.clone();
                                        let ctx_clone = ctx.clone();
                                        tokio::spawn(async move {
                                            if let Ok(network_service) = crate::network::P2PNetwork::new_with_keypair(key_clone, cmd_rx, evt_tx, ctx_clone).await {
                                                network_service.run().await;
                                            }
                                        });

                                        self.auth_state = AppAuthState::Unlocked;
                                    }
                                }
                            }
                        } else {
                            ui.group(|ui| {
                                ui.set_max_width(450.0);
                                ui.label("Local Profile/Account Name:");
                                ui.text_edit_singleline(&mut self.new_profile_name_input);
                                ui.add_space(10.0);
                                ui.label("Paste Backup Code:");
                                ui.add(egui::TextEdit::multiline(&mut self.backup_input)
                                    .hint_text("Paste your base64 encrypted backup code here...")
                                    .desired_rows(6));
                                ui.add_space(10.0);
                                ui.label("Backup Master Password:");
                                ui.add(egui::TextEdit::singleline(&mut self.password_input).password(true));
                            });

                            if let Some(err) = &self.password_error {
                                ui.add_space(8.0);
                                ui.colored_label(egui::Color32::from_rgb(230, 80, 80), err);
                            }

                            ui.add_space(20.0);
                            if ui.add(egui::Button::new("Restore Profile").min_size(egui::vec2(160.0, 36.0))).clicked()
                                && !self.new_profile_name_input.is_empty() && !self.backup_input.is_empty() && !self.password_input.is_empty()
                            {
                                let sanitized_name = self.new_profile_name_input.trim().replace(" ", "_");
                                let file_path = get_profile_path(&sanitized_name);

                                if std::path::Path::new(&file_path).exists() {
                                    self.password_error = Some("A profile with this name already exists.".to_string());
                                } else {
                                    let backup_trimmed = self.backup_input.trim();
                                    if let Ok(encrypted_bytes) = general_purpose::STANDARD.decode(backup_trimmed) {
                                        let mut hasher = sha2::Sha256::new();
                                        hasher.update(self.password_input.as_bytes());
                                        let key_bytes: [u8; 32] = hasher.finalize().into();

                                        let nonce = [0u8; 16];
                                        let mut cipher = crate::crypto::CustomCipher::new(&key_bytes, &nonce);
                                        let decrypted_bytes = cipher.decrypt(&encrypted_bytes);

                                        if let Ok(json_str) = String::from_utf8(decrypted_bytes) {
                                            if let Ok(profile) = serde_json::from_str::<SavedProfile>(&json_str) {
                                                self.selected_profile_name = sanitized_name;
                                                self.my_username = profile.username;
                                                self.my_keypair_protobuf = hex::decode(profile.keypair_protobuf_hex).unwrap_or_default();

                                                for f in profile.friends {
                                                    if let Ok(peer_id) = f.peer_id.parse::<PeerId>() {
                                                        self.friends.insert(peer_id, FriendState {
                                                            peer_id,
                                                            username: f.username,
                                                            status: FriendStatus::Disconnected,
                                                            is_pending_approval: f.is_pending_approval.unwrap_or(false),
                                                            messages: f.messages,
                                                            call: CallState::Idle,
                                                        });
                                                    }
                                                }

                                                let _ = save_profile(
                                                    &file_path,
                                                    &self.password_input,
                                                    &self.my_keypair_protobuf,
                                                    &self.my_username,
                                                    &self.friends,
                                                );

                                                let (cmd_tx, cmd_rx) = mpsc::channel(100);
                                                let (evt_tx, evt_rx) = mpsc::channel(100);
                                                self.cmd_tx = Some(cmd_tx);
                                                self.evt_rx = Some(evt_rx);

                                                let key_clone = self.my_keypair_protobuf.clone();
                                                let ctx_clone = ctx.clone();
                                                tokio::spawn(async move {
                                                    if let Ok(network_service) = crate::network::P2PNetwork::new_with_keypair(key_clone, cmd_rx, evt_tx, ctx_clone).await {
                                                        network_service.run().await;
                                                    }
                                                });

                                                self.auth_state = AppAuthState::Unlocked;
                                            } else {
                                                self.password_error = Some("Decrypted data is not a valid profile.".to_string());
                                            }
                                        } else {
                                            self.password_error = Some("Incorrect password or corrupted backup code.".to_string());
                                        }
                                    } else {
                                        self.password_error = Some("Invalid backup code encoding (not base64).".to_string());
                                    }
                                }
                            }
                        }

                        ui.add_space(20.0);
                        if ui.button("Back to Account Selector").clicked() {
                            self.available_profiles = list_profiles();
                            if self.available_profiles.is_empty() {
                                self.auth_state = AppAuthState::CreateProfile;
                            } else {
                                self.auth_state = AppAuthState::SelectProfile;
                            }
                        }
                    });
                });
                return;
            }
            AppAuthState::UnlockProfile => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(140.0);
                        ui.heading(format!("Unlock Profile: {}", self.selected_profile_name));
                        ui.add_space(8.0);
                        ui.label("Enter your master password to decrypt your profile, keys, and contact list.");
                        ui.add_space(20.0);

                        ui.group(|ui| {
                            ui.set_max_width(320.0);
                            ui.label("Master Password:");
                            ui.add(egui::TextEdit::singleline(&mut self.password_input).password(true));
                        });

                        if let Some(err) = &self.password_error {
                            ui.add_space(8.0);
                            ui.colored_label(egui::Color32::from_rgb(230, 80, 80), err);
                        }

                        ui.add_space(20.0);
                        ui.horizontal(|ui| {
                            ui.add_space(425.0);
                            if ui.add(egui::Button::new("Unlock").min_size(egui::vec2(100.0, 36.0))).clicked() && !self.password_input.is_empty() {
                                let file_path = get_profile_path(&self.selected_profile_name);
                                match load_profile(&file_path, &self.password_input) {
                                    Ok(profile) => {
                                        self.my_username = profile.username;
                                        self.my_keypair_protobuf = hex::decode(profile.keypair_protobuf_hex).unwrap_or_default();

                                        for f in profile.friends {
                                            if let Ok(peer_id) = f.peer_id.parse::<PeerId>() {
                                                self.friends.insert(peer_id, FriendState {
                                                    peer_id,
                                                    username: f.username,
                                                    status: FriendStatus::Disconnected,
                                                    is_pending_approval: f.is_pending_approval.unwrap_or(false),
                                                    messages: f.messages,
                                                    call: CallState::Idle,
                                                });
                                            }
                                        }

                                        let (cmd_tx, cmd_rx) = mpsc::channel(100);
                                        let (evt_tx, evt_rx) = mpsc::channel(100);
                                        self.cmd_tx = Some(cmd_tx);
                                        self.evt_rx = Some(evt_rx);

                                        let key_clone = self.my_keypair_protobuf.clone();
                                        let ctx_clone = ctx.clone();
                                        tokio::spawn(async move {
                                            if let Ok(network_service) = crate::network::P2PNetwork::new_with_keypair(key_clone, cmd_rx, evt_tx, ctx_clone).await {
                                                network_service.run().await;
                                            }
                                        });

                                        self.auth_state = AppAuthState::Unlocked;
                                    }
                                    Err(_) => {
                                        self.password_error = Some("Incorrect Master Password.".to_string());
                                    }
                                }
                            }
                            ui.add_space(10.0);
                            if ui.add(egui::Button::new("Cancel").min_size(egui::vec2(100.0, 36.0))).clicked() {
                                self.available_profiles = list_profiles();
                                self.auth_state = AppAuthState::SelectProfile;
                            }
                        });
                    });
                });
                return;
            }
            AppAuthState::Unlocked => {}
        }

        let mut friends_changed = false;

        if let Some(rx) = &mut self.evt_rx {
            while let Ok(evt) = rx.try_recv() {
                match evt {
                    NetworkEvent::MyPeerId(peer_id) => {
                        self.local_peer_id = Some(peer_id);
                    }
                    NetworkEvent::NewRelayedAddress(addr) => {
                        if !self.my_addresses.contains(&addr) {
                            self.my_addresses.push(addr);
                        }
                    }
                    NetworkEvent::FriendStatus { peer_id, status } => {
                        let default_name = format!("@user_{}", &peer_id.to_string()[..5]);
                        self.friends
                            .entry(peer_id)
                            .and_modify(|f| f.status = status)
                            .or_insert_with(|| {
                                friends_changed = true;
                                FriendState {
                                    peer_id,
                                    username: default_name,
                                    status,
                                    is_pending_approval: true,
                                    messages: Vec::new(),
                                    call: CallState::Idle,
                                }
                            });
                    }
                    NetworkEvent::FriendUsername { peer_id, username } => {
                        self.friends
                            .entry(peer_id)
                            .and_modify(|f| {
                                if f.username != username {
                                    f.username = username.clone();
                                    friends_changed = true;
                                }
                            })
                            .or_insert_with(|| {
                                friends_changed = true;
                                FriendState {
                                    peer_id,
                                    username: username.clone(),
                                    status: FriendStatus::Disconnected,
                                    is_pending_approval: true,
                                    messages: Vec::new(),
                                    call: CallState::Idle,
                                }
                            });
                    }
                    NetworkEvent::IncomingPayload { peer_id, payload } => {
                        let content = match payload {
                            InnerPayload::TextMessage { text } => ChatMessageContent::Text(text),
                            InnerPayload::FileTransfer {
                                file_name,
                                mime_type,
                                file_bytes_base64,
                            } => {
                                let bytes = general_purpose::STANDARD
                                    .decode(file_bytes_base64)
                                    .unwrap_or_default();
                                ChatMessageContent::File {
                                    name: file_name,
                                    mime: mime_type,
                                    bytes,
                                }
                            }
                            InnerPayload::PhotoTransfer {
                                file_name,
                                image_bytes_base64,
                            } => {
                                let bytes = general_purpose::STANDARD
                                    .decode(image_bytes_base64)
                                    .unwrap_or_default();
                                ChatMessageContent::Photo {
                                    name: file_name,
                                    bytes,
                                }
                            }
                            InnerPayload::VideoTransfer {
                                file_name,
                                video_bytes_base64,
                            } => {
                                let bytes = general_purpose::STANDARD
                                    .decode(video_bytes_base64)
                                    .unwrap_or_default();
                                ChatMessageContent::Video {
                                    name: file_name,
                                    bytes,
                                }
                            }
                            InnerPayload::VoiceNoteTransfer {
                                duration_secs,
                                audio_bytes_base64,
                            } => {
                                let bytes = general_purpose::STANDARD
                                    .decode(audio_bytes_base64)
                                    .unwrap_or_default();
                                ChatMessageContent::VoiceNote {
                                    duration: duration_secs,
                                    bytes,
                                    is_playing: false,
                                }
                            }
                        };

                        let msg = ChatMessage {
                            is_ours: false,
                            timestamp: "now".to_string(),
                            content,
                        };

                        let default_name = format!("@user_{}", &peer_id.to_string()[..5]);
                        self.friends
                            .entry(peer_id)
                            .and_modify(|f| f.messages.push(msg.clone()))
                            .or_insert_with(|| FriendState {
                                peer_id,
                                username: default_name,
                                status: FriendStatus::Secure,
                                is_pending_approval: true,
                                messages: vec![msg],
                                call: CallState::Idle,
                            });
                        friends_changed = true;
                    }
                    NetworkEvent::IncomingCallSignal { peer_id, signal } => {
                        let default_name = format!("@user_{}", &peer_id.to_string()[..5]);
                        let state = self.friends.entry(peer_id).or_insert_with(|| {
                            friends_changed = true;
                            FriendState {
                                peer_id,
                                username: default_name,
                                status: FriendStatus::Secure,
                                is_pending_approval: true,
                                messages: Vec::new(),
                                call: CallState::Idle,
                            }
                        });

                        match signal {
                            CallSignalType::Dial => {
                                state.call = CallState::Ringing;
                            }
                            CallSignalType::Accept => {
                                state.call = CallState::Active {
                                    duration_secs: 0,
                                    is_muted: false,
                                };
                            }
                            CallSignalType::Decline | CallSignalType::HangUp => {
                                state.call = CallState::Idle;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if friends_changed {
            let file_path = get_profile_path(&self.selected_profile_name);
            let _ = save_profile(
                &file_path,
                &self.password_input,
                &self.my_keypair_protobuf,
                &self.my_username,
                &self.friends,
            );
        }

        if self.recording_voice_note {
            ctx.request_repaint_after(Duration::from_secs(1));
        }

        if self.show_export_window {
            egui::Window::new("Account Backup")
                .open(&mut self.show_export_window)
                .default_size([450.0, 300.0])
                .show(ctx, |ui| {
                    ui.label("This is your encrypted backup code. It contains your private keys, profile details, friends, and all chat history. Save it safely to restore your account on any device.");
                    ui.add_space(8.0);
                    if let Some(code) = &self.exported_backup_code {
                        ui.add(egui::TextEdit::multiline(&mut code.clone())
                            .desired_rows(6)
                            .lock_focus(true));
                        ui.add_space(10.0);
                        if ui.button("Copy to Clipboard").clicked() {
                            ui.output_mut(|o| o.copied_text = code.clone());
                        }
                    }
                });
        }

        egui::SidePanel::left("left_panel")
            .resizable(false)
            .default_width(340.0)
            .show(ctx, |ui| {
                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("noto-m").heading().color(egui::Color32::from_rgb(110, 180, 255)));
                    ui.add_space(4.0);
                    if self.my_addresses.is_empty() {
                        ui.colored_label(egui::Color32::from_rgb(220, 160, 40), "[Connecting]");
                    } else {
                        ui.colored_label(egui::Color32::from_rgb(40, 200, 100), "[Network Active]");
                    }
                });

                ui.add_space(12.0);

                if let Some(peer_id) = &self.local_peer_id {
                    let p_str = peer_id.to_string();
                    let short_peer = format!("{}...{}", &p_str[..7], &p_str[p_str.len() - 7..]);

                    ui.group(|ui| {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Username:").strong());
                                if ui.text_edit_singleline(&mut self.my_username).changed() {
                                    if let Some(tx) = &self.cmd_tx {
                                        let _ = tx.try_send(UiCommand::UpdateUsername {
                                            username: self.my_username.clone(),
                                        });
                                    }
                                    let file_path = get_profile_path(&self.selected_profile_name);
                                    let _ = save_profile(
                                        &file_path,
                                        &self.password_input,
                                        &self.my_keypair_protobuf,
                                        &self.my_username,
                                        &self.friends,
                                    );
                                }
                            });

                            ui.add_space(6.0);

                            ui.label(egui::RichText::new("My Address:").strong());
                            ui.horizontal(|ui| {
                                ui.colored_label(egui::Color32::from_rgb(170, 180, 195), short_peer);
                                if ui.button("Copy").clicked() {
                                    ui.output_mut(|o| o.copied_text = p_str.clone());
                                }
                            });

                            ui.add_space(8.0);

                            let invite_struct = serde_json::json!({
                                "peer_id": p_str,
                                "addresses": self.my_addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                                "username": Some(self.my_username.clone())
                            });
                            let invite_json = serde_json::to_vec(&invite_struct).unwrap();
                            let invite_code = general_purpose::STANDARD.encode(&invite_json);

                            ui.horizontal(|ui| {
                                if ui.add(egui::Button::new(egui::RichText::new("Copy Invite Code").strong())).clicked() {
                                    ui.output_mut(|o| o.copied_text = invite_code);
                                }

                                if ui.button("Backup Profile").clicked() {
                                    let file_path = get_profile_path(&self.selected_profile_name);
                                    if let Ok(encrypted_bytes) = std::fs::read(&file_path) {
                                        let base64_backup = general_purpose::STANDARD.encode(&encrypted_bytes);
                                        self.exported_backup_code = Some(base64_backup);
                                        self.show_export_window = true;
                                    }
                                }
                            });
                        });
                    });
                }

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(15.0);

                ui.label(egui::RichText::new("Add Friend:").strong());
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.invite_input)
                        .hint_text("Paste friend's code here...")
                        .margin(egui::vec2(8.0, 8.0)));

                    if ui.add(egui::Button::new("Add").min_size(egui::vec2(60.0, 30.0))).clicked() && !self.invite_input.is_empty() {
                        if let Some(tx) = &self.cmd_tx {
                            let _ = tx.try_send(UiCommand::AddFriend {
                                invite_code: self.invite_input.clone(),
                            });
                        }
                        self.invite_input.clear();
                    }
                });

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(15.0);

                ui.label(egui::RichText::new("Conversations:").strong());
                ui.add_space(8.0);

                egui::ScrollArea::vertical().show(ui, |ui| {
                    if self.friends.is_empty() {
                        ui.colored_label(egui::Color32::GRAY, "No friends added. Copy your invitation code above and share it.");
                    } else {
                        for (peer_id, friend) in &self.friends {
                            let is_selected = Some(*peer_id) == self.active_friend;

                            let (status_color, status_text) = if friend.is_pending_approval {
                                (egui::Color32::from_rgb(220, 160, 40), "Pending Approval")
                            } else {
                                match friend.status {
                                    FriendStatus::Secure => (egui::Color32::from_rgb(40, 200, 100), "Online (Secure)"),
                                    FriendStatus::Securing | FriendStatus::Connecting => (egui::Color32::from_rgb(220, 160, 40), "Connecting..."),
                                    FriendStatus::Connected => (egui::Color32::from_rgb(60, 150, 240), "Connected"),
                                    FriendStatus::Disconnected => (egui::Color32::from_rgb(230, 80, 80), "Offline"),
                                }
                            };

                            let frame_color = if is_selected {
                                egui::Color32::from_rgb(46, 56, 70)
                            } else {
                                egui::Color32::from_rgb(28, 34, 42)
                            };

                            let resp = egui::Frame::default()
                                .fill(frame_color)
                                .rounding(8.0)
                                .inner_margin(8.0)
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.vertical(|ui| {
                                            ui.label(egui::RichText::new(&friend.username).strong());
                                            ui.colored_label(status_color, status_text);
                                        });
                                    });
                                }).response;

                            let clicked = resp.interact(egui::Sense::click()).clicked();
                            if clicked {
                                self.active_friend = Some(*peer_id);
                            }
                        }
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
                    if let Some(active_peer_ref) = &self.active_friend {
                        let active_peer = *active_peer_ref;
                        if let Some(friend) = self.friends.get(&active_peer).cloned() {
                            ui.horizontal(|ui| {
                                ui.heading(&friend.username);
                                ui.add_space(10.0);
                                if friend.status == FriendStatus::Secure && !friend.is_pending_approval {
                                    ui.colored_label(egui::Color32::from_rgb(40, 200, 100), "[Secure] (Zenith-Sponge Active)");
                                }

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if friend.call == CallState::Idle && !friend.is_pending_approval {
                                        if ui.add(egui::Button::new("Call").fill(egui::Color32::from_rgb(40, 160, 80))).clicked() {
                                            if let Some(tx) = &self.cmd_tx {
                                                let _ = tx.try_send(UiCommand::SendCallSignal {
                                                    peer_id: active_peer,
                                                    signal: CallSignalType::Dial,
                                                });
                                            }
                                            self.friends.entry(active_peer).and_modify(|f| f.call = CallState::Dialing);
                                        }
                                    }
                                });
                            });
                            ui.separator();
                            ui.add_space(8.0);

                            if friend.is_pending_approval {
                                ui.group(|ui| {
                                    ui.vertical_centered(|ui| {
                                        ui.label(egui::RichText::new(format!("Connection request from {}", friend.username)).heading());
                                        ui.label("This user has initiated a direct secure connection with you. Do you want to accept and add them to your contacts list?");
                                        ui.add_space(15.0);
                                        ui.horizontal(|ui| {
                                            ui.add_space(310.0);
                                            if ui.add(egui::Button::new("Accept Request").fill(egui::Color32::from_rgb(40, 160, 80)).min_size(egui::vec2(120.0, 32.0))).clicked() {
                                                self.friends.entry(active_peer).and_modify(|f| f.is_pending_approval = false);
                                                let file_path = get_profile_path(&self.selected_profile_name);
                                                let _ = save_profile(
                                                    &file_path,
                                                    &self.password_input,
                                                    &self.my_keypair_protobuf,
                                                    &self.my_username,
                                                    &self.friends,
                                                );
                                            }
                                            ui.add_space(10.0);
                                            if ui.add(egui::Button::new("Decline").fill(egui::Color32::from_rgb(200, 60, 60)).min_size(egui::vec2(100.0, 32.0))).clicked() {
                                                self.friends.remove(&active_peer);
                                                self.active_friend = None;
                                                let file_path = get_profile_path(&self.selected_profile_name);
                                                let _ = save_profile(
                                                    &file_path,
                                                    &self.password_input,
                                                    &self.my_keypair_protobuf,
                                                    &self.my_username,
                                                    &self.friends,
                                                );
                                            }
                                        });
                                    });
                                });
                                return;
                            }

                            match friend.call {
                                CallState::Dialing => {
                                    ui.group(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.spinner();
                                            ui.label("Calling friend...");
                                            if ui.button("Cancel").clicked() {
                                                if let Some(tx) = &self.cmd_tx {
                                                    let _ = tx.try_send(UiCommand::SendCallSignal {
                                                        peer_id: active_peer,
                                                        signal: CallSignalType::HangUp,
                                                    });
                                                }
                                                self.friends.entry(active_peer).and_modify(|f| f.call = CallState::Idle);
                                            }
                                        });
                                    });
                                }
                                CallState::Ringing => {
                                    ui.group(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.colored_label(egui::Color32::from_rgb(220, 160, 40), "Incoming secure voice call...");
                                            if ui.add(egui::Button::new("Accept").fill(egui::Color32::from_rgb(40, 160, 80))).clicked() {
                                                if let Some(tx) = &self.cmd_tx {
                                                    let _ = tx.try_send(UiCommand::SendCallSignal {
                                                        peer_id: active_peer,
                                                        signal: CallSignalType::Accept,
                                                    });
                                                }
                                                self.friends.entry(active_peer).and_modify(|f| f.call = CallState::Active { duration_secs: 0, is_muted: false });
                                            }
                                            if ui.add(egui::Button::new("Decline").fill(egui::Color32::from_rgb(200, 60, 60))).clicked() {
                                                if let Some(tx) = &self.cmd_tx {
                                                    let _ = tx.try_send(UiCommand::SendCallSignal {
                                                        peer_id: active_peer,
                                                        signal: CallSignalType::Decline,
                                                    });
                                                }
                                                self.friends.entry(active_peer).and_modify(|f| f.call = CallState::Idle);
                                            }
                                        });
                                    });
                                }
                                CallState::Active { duration_secs, is_muted } => {
                                    ui.group(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.colored_label(egui::Color32::from_rgb(40, 200, 100), "Call Active");
                                            ui.label(format!("Time: {:02}:{:02}", duration_secs / 60, duration_secs % 60));

                                            let mute_text = if is_muted { "Unmute" } else { "Mute" };
                                            if ui.button(mute_text).clicked() {
                                                self.friends.entry(active_peer).and_modify(|f| {
                                                    if let CallState::Active { is_muted: m, .. } = &mut f.call {
                                                        *m = !*m;
                                                    }
                                                });
                                            }
                                            if ui.add(egui::Button::new("Hang Up").fill(egui::Color32::from_rgb(200, 60, 60))).clicked() {
                                                if let Some(tx) = &self.cmd_tx {
                                                    let _ = tx.try_send(UiCommand::SendCallSignal {
                                                        peer_id: active_peer,
                                                        signal: CallSignalType::HangUp,
                                                    });
                                                }
                                                self.friends.entry(active_peer).and_modify(|f| f.call = CallState::Idle);
                                            }
                                        });

                                        ui.add_space(5.0);
                                        let mut points = vec![];
                                        let time = ctx.input(|i| i.time);
                                        for x in 0..150 {
                                            let y = if is_muted {
                                                0.0
                                            } else {
                                                ((x as f64 * 0.15 + time * 8.0).sin() * 8.0 + (x as f64 * 0.35 - time * 12.0).cos() * 4.0) as f32
                                            };
                                            points.push(egui::pos2(120.0 + x as f32 * 2.0, 35.0 + y));
                                        }
                                        let color = if is_muted { egui::Color32::GRAY } else { egui::Color32::from_rgb(40, 200, 100) };
                                        ui.painter().add(egui::Shape::line(points, egui::Stroke::new(1.8_f32, color)));
                                        ui.add_space(15.0);
                                    });
                                }
                                _ => {}
                            }

                            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                                ui.add_space(10.0);
                                ui.horizontal(|ui| {
                                    if ui.button("Attach Document").clicked() {
                                        let simulated_content = "NOTO_SECURE_MEDIA_P2P_STREAM_TEST_CONTENT";
                                        let base64_payload = general_purpose::STANDARD.encode(simulated_content.as_bytes());

                                        let payload = InnerPayload::FileTransfer {
                                            file_name: "Document.txt".to_string(),
                                            mime_type: "text/plain".to_string(),
                                            file_bytes_base64: base64_payload,
                                        };

                                        if let Some(tx) = &self.cmd_tx {
                                            let _ = tx.try_send(UiCommand::SendPayload {
                                                peer_id: active_peer,
                                                payload: payload.clone(),
                                            });
                                        }

                                        self.friends.entry(active_peer).and_modify(|f| {
                                            f.messages.push(ChatMessage {
                                                is_ours: true,
                                                timestamp: "now".to_string(),
                                                content: ChatMessageContent::File {
                                                    name: "Document.txt".to_string(),
                                                    mime: "text/plain".to_string(),
                                                    bytes: simulated_content.as_bytes().to_vec(),
                                                },
                                            });
                                        });

                                        let file_path = get_profile_path(&self.selected_profile_name);
                                        let _ = save_profile(
                                            &file_path,
                                            &self.password_input,
                                            &self.my_keypair_protobuf,
                                            &self.my_username,
                                            &self.friends,
                                        );
                                    }

                                    if ui.button("Attach Photo").clicked() {
                                        let dummy_img_data = vec![0u8; 1024];
                                        let base64_payload = general_purpose::STANDARD.encode(&dummy_img_data);

                                        let payload = InnerPayload::PhotoTransfer {
                                            file_name: "Photo.png".to_string(),
                                            image_bytes_base64: base64_payload,
                                        };

                                        if let Some(tx) = &self.cmd_tx {
                                            let _ = tx.try_send(UiCommand::SendPayload {
                                                peer_id: active_peer,
                                                payload: payload.clone(),
                                            });
                                        }

                                        self.friends.entry(active_peer).and_modify(|f| {
                                            f.messages.push(ChatMessage {
                                                is_ours: true,
                                                timestamp: "now".to_string(),
                                                content: ChatMessageContent::Photo {
                                                    name: "Photo.png".to_string(),
                                                    bytes: dummy_img_data,
                                                },
                                            });
                                        });

                                        let file_path = get_profile_path(&self.selected_profile_name);
                                        let _ = save_profile(
                                            &file_path,
                                            &self.password_input,
                                            &self.my_keypair_protobuf,
                                            &self.my_username,
                                            &self.friends,
                                        );
                                    }

                                    if ui.button("Attach Video").clicked() {
                                        let dummy_video_data = vec![0u8; 1024];
                                        let base64_payload = general_purpose::STANDARD.encode(&dummy_video_data);

                                        let payload = InnerPayload::VideoTransfer {
                                            file_name: "Video.mp4".to_string(),
                                            video_bytes_base64: base64_payload,
                                        };

                                        if let Some(tx) = &self.cmd_tx {
                                            let _ = tx.try_send(UiCommand::SendPayload {
                                                peer_id: active_peer,
                                                payload: payload.clone(),
                                            });
                                        }

                                        self.friends.entry(active_peer).and_modify(|f| {
                                            f.messages.push(ChatMessage {
                                                is_ours: true,
                                                timestamp: "now".to_string(),
                                                content: ChatMessageContent::Video {
                                                    name: "Video.mp4".to_string(),
                                                    bytes: dummy_video_data,
                                                },
                                            });
                                        });

                                        let file_path = get_profile_path(&self.selected_profile_name);
                                        let _ = save_profile(
                                            &file_path,
                                            &self.password_input,
                                            &self.my_keypair_protobuf,
                                            &self.my_username,
                                            &self.friends,
                                        );
                                    }

                                    let voice_label = if self.recording_voice_note { "Stop Recording" } else { "Record Voice" };
                                    if ui.button(voice_label).clicked() {
                                        if !self.recording_voice_note {
                                            self.recording_voice_note = true;
                                            self.recorded_secs = 5;
                                        } else {
                                            self.recording_voice_note = false;
                                            let audio_mock = vec![0u8; 512];
                                            let base64_payload = general_purpose::STANDARD.encode(&audio_mock);

                                            let payload = InnerPayload::VoiceNoteTransfer {
                                                duration_secs: self.recorded_secs,
                                                audio_bytes_base64: base64_payload,
                                            };

                                            if let Some(tx) = &self.cmd_tx {
                                                let _ = tx.try_send(UiCommand::SendPayload {
                                                    peer_id: active_peer,
                                                    payload: payload.clone(),
                                                });
                                            }

                                            self.friends.entry(active_peer).and_modify(|f| {
                                                f.messages.push(ChatMessage {
                                                    is_ours: true,
                                                    timestamp: "now".to_string(),
                                                    content: ChatMessageContent::VoiceNote {
                                                        duration: self.recorded_secs,
                                                        bytes: audio_mock,
                                                        is_playing: false,
                                                    },
                                                });
                                            });

                                            let file_path = get_profile_path(&self.selected_profile_name);
                                            let _ = save_profile(
                                                &file_path,
                                                &self.password_input,
                                                &self.my_keypair_protobuf,
                                                &self.my_username,
                                                &self.friends,
                                            );
                                        }
                                    }
                                });

                                ui.add_space(5.0);

                                ui.horizontal(|ui| {
                                    let input_width = ui.available_width() - 95.0;
                                    let text_edit = ui.add(egui::TextEdit::singleline(&mut self.message_input)
                                        .hint_text("Type a secure message...")
                                        .desired_width(input_width)
                                        .margin(egui::vec2(10.0, 10.0)));

                                    let send_clicked = ui.add(egui::Button::new("Send").min_size(egui::vec2(80.0, 36.0))).clicked();

                                    if (send_clicked || (text_edit.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter))))
                                        && !self.message_input.is_empty()
                                    {
                                        let inner = InnerPayload::TextMessage { text: self.message_input.clone() };
                                        if let Some(tx) = &self.cmd_tx {
                                            let _ = tx.try_send(UiCommand::SendPayload {
                                                peer_id: active_peer,
                                                payload: inner,
                                            });
                                        }

                                        let local_msg = ChatMessage {
                                            is_ours: true,
                                            timestamp: "now".to_string(),
                                            content: ChatMessageContent::Text(self.message_input.clone()),
                                        };
                                        self.friends.entry(active_peer).and_modify(|f| f.messages.push(local_msg));
                                        self.message_input.clear();

                                        let file_path = get_profile_path(&self.selected_profile_name);
                                        let _ = save_profile(
                                            &file_path,
                                            &self.password_input,
                                            &self.my_keypair_protobuf,
                                            &self.my_username,
                                            &self.friends,
                                        );
                                    }
                                });

                                ui.separator();

                                egui::ScrollArea::vertical()
                                    .auto_shrink([false; 2])
                                    .stick_to_bottom(true)
                                    .show_rows(ui, ui.text_style_height(&egui::TextStyle::Body), friend.messages.len(), |ui, row_range| {
                                        for idx in row_range {
                                            let msg = &friend.messages[idx];
                                            ui.add_space(6.0);
                                            ui.horizontal(|ui| {
                                                if msg.is_ours {
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        egui::Frame::default()
                                                            .fill(egui::Color32::from_rgb(52, 116, 212))
                                                            .rounding(egui::Rounding {
                                                                nw: 14.0, ne: 14.0, sw: 14.0, se: 0.0
                                                            })
                                                            .inner_margin(10.0)
                                                            .show(ui, |ui| {
                                                                match &msg.content {
                                                                    ChatMessageContent::Text(text) => {
                                                                        ui.colored_label(egui::Color32::WHITE, text);
                                                                    }
                                                                    ChatMessageContent::File { name, mime: _, bytes: _ } => {
                                                                        ui.colored_label(egui::Color32::WHITE, format!("[File] {}", name));
                                                                    }
                                                                    ChatMessageContent::Photo { name, bytes: _ } => {
                                                                        ui.colored_label(egui::Color32::WHITE, format!("[Photo] {}", name));
                                                                    }
                                                                    ChatMessageContent::Video { name, bytes: _ } => {
                                                                        ui.colored_label(egui::Color32::WHITE, format!("[Video] {}", name));
                                                                    }
                                                                    ChatMessageContent::VoiceNote { duration, bytes: _, is_playing: _ } => {
                                                                        ui.colored_label(egui::Color32::WHITE, format!("[Voice Note] ({}s)", duration));
                                                                    }
                                                                }
                                                            });
                                                    });
                                                } else {
                                                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                        egui::Frame::default()
                                                            .fill(egui::Color32::from_rgb(38, 44, 54))
                                                            .rounding(egui::Rounding {
                                                                nw: 14.0, ne: 14.0, sw: 0.0, se: 14.0
                                                            })
                                                            .inner_margin(10.0)
                                                            .show(ui, |ui| {
                                                                match &msg.content {
                                                                    ChatMessageContent::Text(text) => {
                                                                        ui.colored_label(egui::Color32::from_rgb(220, 225, 235), text);
                                                                    }
                                                                    ChatMessageContent::File { name, mime, bytes } => {
                                                                        ui.vertical(|ui| {
                                                                            ui.colored_label(egui::Color32::WHITE, format!("[File] {}", name));
                                                                            ui.colored_label(egui::Color32::GRAY, mime);
                                                                            if ui.button("Extract Text").clicked() {
                                                                                ui.output_mut(|o| o.copied_text = String::from_utf8_lossy(bytes).into_owned());
                                                                            }
                                                                        });
                                                                    }
                                                                    ChatMessageContent::Photo { name, bytes: _ } => {
                                                                        ui.vertical(|ui| {
                                                                            ui.colored_label(egui::Color32::WHITE, format!("[Photo] {}", name));
                                                                            let size = egui::vec2(150.0, 95.0);
                                                                            let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
                                                                            ui.painter().rect_filled(rect, 8.0, egui::Color32::from_rgb(20, 24, 30));
                                                                            ui.painter().text(
                                                                                rect.center(),
                                                                                egui::Align2::CENTER_CENTER,
                                                                                "Image Received",
                                                                                egui::FontId::proportional(12.0),
                                                                                egui::Color32::GRAY
                                                                            );
                                                                        });
                                                                    }
                                                                    ChatMessageContent::Video { name, bytes: _ } => {
                                                                        ui.vertical(|ui| {
                                                                            ui.colored_label(egui::Color32::WHITE, format!("[Video] {}", name));
                                                                            let size = egui::vec2(150.0, 95.0);
                                                                            let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
                                                                            ui.painter().rect_filled(rect, 8.0, egui::Color32::from_rgb(20, 24, 30));
                                                                            ui.painter().text(
                                                                                rect.center(),
                                                                                egui::Align2::CENTER_CENTER,
                                                                                "Video Received\nClick to Play",
                                                                                egui::FontId::proportional(12.0),
                                                                                egui::Color32::GRAY
                                                                            );
                                                                        });
                                                                    }
                                                                    ChatMessageContent::VoiceNote { duration, bytes: _, is_playing: _ } => {
                                                                        ui.horizontal(|ui| {
                                                                            ui.colored_label(egui::Color32::WHITE, "[Voice Note]");
                                                                            ui.colored_label(egui::Color32::from_rgb(40, 200, 100), format!("{}s", duration));
                                                                        });
                                                                    }
                                                                }
                                                            });
                                                    });
                                                }
                                            });
                                        }
                                    });
                            });
                        }
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.vertical_centered(|ui| {
                                ui.add_space(100.0);
                                ui.label(egui::RichText::new("Welcome to Noto-m!").heading().color(egui::Color32::WHITE));
                                ui.add_space(10.0);
                                ui.label(egui::RichText::new("Secure chat without servers, ads, or tracking.").color(egui::Color32::GRAY));

                                ui.add_space(30.0);

                                ui.group(|ui| {
                                    ui.set_max_width(400.0);
                                    ui.label(egui::RichText::new("How to start chatting:").strong());
                                    ui.add_space(8.0);
                                    ui.label("1. Click the 'Copy Invite Code' button in the left panel.");
                                    ui.label("2. Send this code to your friend via any SMS or messenger.");
                                    ui.label("3. Get your friend's code, paste it in the field on the left, and click 'Add'.");
                                });
                            });
                        });
                    }
                });
    }
}
