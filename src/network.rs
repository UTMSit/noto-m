#![allow(dead_code)]

use crate::crypto::CustomCipher;
use base64::{engine::general_purpose, Engine as _};
use libp2p::{
    dcutr, identify, identity, kad, relay, request_response, tcp, yamux, Multiaddr, PeerId,
    StreamProtocol, Swarm, SwarmBuilder,
};
use rand::RngCore;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub const PUBLIC_RELAY: &str =
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ";

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum CallSignalType {
    Dial,
    Accept,
    Decline,
    HangUp,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum InnerPayload {
    TextMessage {
        text: String,
    },
    FileTransfer {
        file_name: String,
        mime_type: String,
        file_bytes_base64: String,
    },
    PhotoTransfer {
        file_name: String,
        image_bytes_base64: String,
    },
    VideoTransfer {
        file_name: String,
        video_bytes_base64: String,
    },
    VoiceNoteTransfer {
        duration_secs: u32,
        audio_bytes_base64: String,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum MessagePayload {
    HandshakeInit {
        public_key_hex: String,
        nonce_hex: String,
        username: String,
    },
    HandshakeResponse {
        public_key_hex: String,
        nonce_hex: String,
        username: String,
    },
    EncryptedContainer {
        ciphertext_hex: String,
        nonce_hex: String,
    },
    CallSignal {
        signal_type: CallSignalType,
    },
    CallAudioFrame {
        sequence: u64,
        audio_data_hex: String,
    },
    Ack,
}

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "NetworkEventOuter")]
pub struct NetworkBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub request_response: request_response::json::Behaviour<MessagePayload, MessagePayload>,
}

#[derive(Debug)]
pub enum NetworkEventOuter {
    Kademlia(kad::Event),
    Identify(identify::Event),
    RelayClient(relay::client::Event),
    Dcutr(dcutr::Event),
    RequestResponse(request_response::Event<MessagePayload, MessagePayload>),
}

impl From<kad::Event> for NetworkEventOuter {
    fn from(event: kad::Event) -> Self {
        Self::Kademlia(event)
    }
}
impl From<identify::Event> for NetworkEventOuter {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}
impl From<relay::client::Event> for NetworkEventOuter {
    fn from(event: relay::client::Event) -> Self {
        Self::RelayClient(event)
    }
}
impl From<dcutr::Event> for NetworkEventOuter {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}
impl From<request_response::Event<MessagePayload, MessagePayload>> for NetworkEventOuter {
    fn from(event: request_response::Event<MessagePayload, MessagePayload>) -> Self {
        Self::RequestResponse(event)
    }
}

#[derive(Debug)]
pub enum UiCommand {
    AddFriend {
        invite_code: String,
    },
    SendPayload {
        peer_id: PeerId,
        payload: InnerPayload,
    },
    SendCallSignal {
        peer_id: PeerId,
        signal: CallSignalType,
    },
    SendAudioFrame {
        peer_id: PeerId,
        sequence: u64,
        raw_audio: Vec<u8>,
    },
    UpdateUsername {
        username: String,
    },
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    MyPeerId(PeerId),
    NewRelayedAddress(Multiaddr),
    FriendStatus {
        peer_id: PeerId,
        status: FriendStatus,
    },
    FriendUsername {
        peer_id: PeerId,
        username: String,
    },
    IncomingPayload {
        peer_id: PeerId,
        payload: InnerPayload,
    },
    IncomingCallSignal {
        peer_id: PeerId,
        signal: CallSignalType,
    },
    IncomingAudioFrame {
        peer_id: PeerId,
        sequence: u64,
        audio_data: Vec<u8>,
    },
    Log(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FriendStatus {
    Disconnected,
    Connecting,
    Connected,
    Securing,
    Secure,
}

pub struct P2PNetwork {
    pub swarm: Swarm<NetworkBehaviour>,
    pub local_peer_id: PeerId,
    cmd_rx: mpsc::Receiver<UiCommand>,
    evt_tx: mpsc::Sender<NetworkEvent>,
    egui_ctx: eframe::egui::Context,

    my_username: String,
    pending_secrets: HashMap<PeerId, EphemeralSecret>,
    shared_secrets: HashMap<PeerId, [u8; 32]>,
}

impl P2PNetwork {
    pub async fn new_with_keypair(
        keypair_protobuf: Vec<u8>,
        cmd_rx: mpsc::Receiver<UiCommand>,
        evt_tx: mpsc::Sender<NetworkEvent>,
        egui_ctx: eframe::egui::Context,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let keypair = identity::Keypair::from_protobuf_encoding(&keypair_protobuf)?;
        let peer_id = PeerId::from(keypair.public());

        let _ = evt_tx.send(NetworkEvent::MyPeerId(peer_id)).await;
        egui_ctx.request_repaint();

        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                libp2p::noise::Config::new,
                yamux::Config::default,
            )?
            .with_relay_client(libp2p::noise::Config::new, yamux::Config::default)?
            .with_behaviour(|_key, relay_behaviour| NetworkBehaviour {
                kademlia: kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id)),
                identify: identify::Behaviour::new(
                    identify::Config::new("/noto-m/1.0.0".to_string(), _key.public())
                        .with_push_listen_addr_updates(true),
                ),
                relay_client: relay_behaviour,
                dcutr: dcutr::Behaviour::new(peer_id),
                request_response: request_response::json::Behaviour::new(
                    [(
                        StreamProtocol::new("/noto-m/sync/1.0.0"),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                ),
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
            .build();

        Ok(Self {
            swarm,
            local_peer_id: peer_id,
            cmd_rx,
            evt_tx,
            egui_ctx,
            my_username: format!("@user_{}", &peer_id.to_string()[..5]),
            pending_secrets: HashMap::new(),
            shared_secrets: HashMap::new(),
        })
    }

    pub async fn run(mut self) {
        if let Err(e) = self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()) {
            let _ = self
                .evt_tx
                .send(NetworkEvent::Log(format!("Local bind error: {:?}", e)))
                .await;
            self.egui_ctx.request_repaint();
        }

        if let Ok(relay_addr) = PUBLIC_RELAY.parse::<Multiaddr>() {
            let _ = self
                .evt_tx
                .send(NetworkEvent::Log(
                    "Connecting to public transport relay...".to_string(),
                ))
                .await;
            self.egui_ctx.request_repaint();
            if let Err(e) = self.swarm.dial(relay_addr.clone()) {
                let _ = self
                    .evt_tx
                    .send(NetworkEvent::Log(format!("Relay dial error: {:?}", e)))
                    .await;
                self.egui_ctx.request_repaint();
            } else {
                let relay_listen_addr = relay_addr.with(libp2p::multiaddr::Protocol::P2pCircuit);
                if let Err(e) = self.swarm.listen_on(relay_listen_addr) {
                    let _ = self
                        .evt_tx
                        .send(NetworkEvent::Log(format!("Relay listen error: {:?}", e)))
                        .await;
                    self.egui_ctx.request_repaint();
                }
            }
        }

        use futures::StreamExt;
        loop {
            tokio::select! {
                cmd = self.cmd_rx.recv() => {
                    if let Some(command) = cmd {
                        self.handle_ui_command(command).await;
                    }
                }
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
            }
        }
    }

    async fn handle_ui_command(&mut self, cmd: UiCommand) {
        match cmd {
            UiCommand::UpdateUsername { username } => {
                self.my_username = username;
            }
            UiCommand::AddFriend { invite_code } => {
                let code_trimmed = invite_code.trim();
                let json_bytes = match general_purpose::STANDARD.decode(code_trimmed) {
                    Ok(b) => b,
                    Err(_) => {
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::Log(
                                "Invalid invite code encoding.".to_string(),
                            ))
                            .await;
                        self.egui_ctx.request_repaint();
                        return;
                    }
                };

                #[derive(serde::Deserialize)]
                struct Invite {
                    peer_id: String,
                    addresses: Vec<String>,
                    username: Option<String>,
                }

                let invite: Invite = match serde_json::from_slice(&json_bytes) {
                    Ok(i) => i,
                    Err(_) => {
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::Log("Invalid invite schema.".to_string()))
                            .await;
                        self.egui_ctx.request_repaint();
                        return;
                    }
                };

                let target_peer = match invite.peer_id.parse::<PeerId>() {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::Log("Malformed invite PeerId.".to_string()))
                            .await;
                        self.egui_ctx.request_repaint();
                        return;
                    }
                };

                if let Some(name) = invite.username {
                    let _ = self
                        .evt_tx
                        .send(NetworkEvent::FriendUsername {
                            peer_id: target_peer,
                            username: name,
                        })
                        .await;
                }

                let _ = self
                    .evt_tx
                    .send(NetworkEvent::Log(format!(
                        "Resolving routing for: {}",
                        target_peer
                    )))
                    .await;
                let _ = self
                    .evt_tx
                    .send(NetworkEvent::FriendStatus {
                        peer_id: target_peer,
                        status: FriendStatus::Connecting,
                    })
                    .await;
                self.egui_ctx.request_repaint();

                for addr_str in invite.addresses {
                    if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&target_peer, addr.clone());
                        let _ = self.swarm.dial(addr);
                    }
                }
            }
            UiCommand::SendPayload { peer_id, payload } => {
                if let Some(shared_secret) = self.shared_secrets.get(&peer_id) {
                    let mut nonce = [0u8; 16];
                    rand::thread_rng().fill_bytes(&mut nonce);
                    let mut cipher = CustomCipher::new(shared_secret, &nonce);

                    let plaintext_json = serde_json::to_vec(&payload).unwrap();
                    let ciphertext = cipher.encrypt(&plaintext_json);

                    let container = MessagePayload::EncryptedContainer {
                        ciphertext_hex: hex::encode(ciphertext),
                        nonce_hex: hex::encode(nonce),
                    };

                    self.swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, container);
                } else {
                    let _ = self
                        .evt_tx
                        .send(NetworkEvent::Log(
                            "No established keys. Unable to encrypt payload.".to_string(),
                        ))
                        .await;
                    self.egui_ctx.request_repaint();
                }
            }
            UiCommand::SendCallSignal { peer_id, signal } => {
                let signal_payload = MessagePayload::CallSignal {
                    signal_type: signal,
                };
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, signal_payload);
            }
            UiCommand::SendAudioFrame {
                peer_id,
                sequence,
                raw_audio,
            } => {
                if let Some(shared_secret) = self.shared_secrets.get(&peer_id) {
                    let mut nonce = [0u8; 16];
                    rand::thread_rng().fill_bytes(&mut nonce);
                    let mut cipher = CustomCipher::new(shared_secret, &nonce);
                    let ciphertext = cipher.encrypt(&raw_audio);

                    let frame_payload = MessagePayload::CallAudioFrame {
                        sequence,
                        audio_data_hex: hex::encode(ciphertext),
                    };
                    self.swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, frame_payload);
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<NetworkEventOuter>) {
        match event {
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                let _ = self
                    .evt_tx
                    .send(NetworkEvent::Log(format!(
                        "Assigned network address: {:?}",
                        address
                    )))
                    .await;
                let _ = self
                    .evt_tx
                    .send(NetworkEvent::NewRelayedAddress(address))
                    .await;
                self.egui_ctx.request_repaint();
            }
            libp2p::swarm::SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let _ = self
                    .evt_tx
                    .send(NetworkEvent::Log(format!(
                        "Established basic transport with {}",
                        peer_id
                    )))
                    .await;
                let _ = self
                    .evt_tx
                    .send(NetworkEvent::FriendStatus {
                        peer_id,
                        status: FriendStatus::Connected,
                    })
                    .await;
                self.egui_ctx.request_repaint();

                if endpoint.is_dialer() {
                    let _ = self
                        .evt_tx
                        .send(NetworkEvent::Log(
                            "Initiating key exchange agreement...".to_string(),
                        ))
                        .await;
                    let _ = self
                        .evt_tx
                        .send(NetworkEvent::FriendStatus {
                            peer_id,
                            status: FriendStatus::Securing,
                        })
                        .await;
                    self.egui_ctx.request_repaint();

                    let mut rng = rand::thread_rng();
                    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
                    let ephemeral_public = PublicKey::from(&ephemeral_secret);
                    let mut nonce = [0u8; 16];
                    rng.fill_bytes(&mut nonce);

                    let init_payload = MessagePayload::HandshakeInit {
                        public_key_hex: hex::encode(ephemeral_public.as_bytes()),
                        nonce_hex: hex::encode(nonce),
                        username: self.my_username.clone(),
                    };

                    self.pending_secrets.insert(peer_id, ephemeral_secret);
                    self.swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, init_payload);
                }
            }
            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                let _ = self
                    .evt_tx
                    .send(NetworkEvent::Log(format!(
                        "Lost transport link to {}",
                        peer_id
                    )))
                    .await;
                let _ = self
                    .evt_tx
                    .send(NetworkEvent::FriendStatus {
                        peer_id,
                        status: FriendStatus::Disconnected,
                    })
                    .await;
                self.shared_secrets.remove(&peer_id);
                self.egui_ctx.request_repaint();
            }
            libp2p::swarm::SwarmEvent::Behaviour(NetworkEventOuter::RequestResponse(
                request_response::Event::Message { peer, message },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => match request {
                    MessagePayload::HandshakeInit {
                        public_key_hex,
                        nonce_hex: _,
                        username,
                    } => {
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::Log(
                                "Incoming handshake invitation.".to_string(),
                            ))
                            .await;
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::FriendStatus {
                                peer_id: peer,
                                status: FriendStatus::Securing,
                            })
                            .await;
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::FriendUsername {
                                peer_id: peer,
                                username,
                            })
                            .await;
                        self.egui_ctx.request_repaint();

                        let bob_secret = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
                        let bob_public = PublicKey::from(&bob_secret);

                        let alice_pub_bytes = match hex::decode(&public_key_hex)
                            .map(|b| <[u8; 32]>::try_from(b))
                        {
                            Ok(Ok(bytes)) => bytes,
                            _ => {
                                let _ = self
                                    .evt_tx
                                    .send(NetworkEvent::Log("Key conversion failed.".to_string()))
                                    .await;
                                self.egui_ctx.request_repaint();
                                return;
                            }
                        };
                        let alice_public = PublicKey::from(alice_pub_bytes);
                        let shared_secret = bob_secret.diffie_hellman(&alice_public);

                        self.shared_secrets.insert(peer, *shared_secret.as_bytes());

                        let mut nonce = [0u8; 16];
                        rand::thread_rng().fill_bytes(&mut nonce);

                        let response_payload = MessagePayload::HandshakeResponse {
                            public_key_hex: hex::encode(bob_public.as_bytes()),
                            nonce_hex: hex::encode(nonce),
                            username: self.my_username.clone(),
                        };

                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, response_payload);
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::FriendStatus {
                                peer_id: peer,
                                status: FriendStatus::Secure,
                            })
                            .await;
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::Log(
                                "Handshake finished. Secure channel active.".to_string(),
                            ))
                            .await;
                        self.egui_ctx.request_repaint();
                    }
                    MessagePayload::EncryptedContainer {
                        ciphertext_hex,
                        nonce_hex,
                    } => {
                        if let Some(shared_secret) = self.shared_secrets.get(&peer) {
                            let ciphertext = match hex::decode(&ciphertext_hex) {
                                Ok(b) => b,
                                _ => return,
                            };
                            let nonce_bytes =
                                match hex::decode(&nonce_hex).map(|b| <[u8; 16]>::try_from(b)) {
                                    Ok(Ok(bytes)) => bytes,
                                    _ => return,
                                };

                            let mut cipher = CustomCipher::new(shared_secret, &nonce_bytes);
                            let decrypted = cipher.decrypt(&ciphertext);
                            if let Ok(payload) = serde_json::from_slice::<InnerPayload>(&decrypted)
                            {
                                let _ = self
                                    .evt_tx
                                    .send(NetworkEvent::IncomingPayload {
                                        peer_id: peer,
                                        payload,
                                    })
                                    .await;
                            }
                            let _ = self
                                .swarm
                                .behaviour_mut()
                                .request_response
                                .send_response(channel, MessagePayload::Ack);
                            self.egui_ctx.request_repaint();
                        }
                    }
                    MessagePayload::CallSignal { signal_type } => {
                        let _ = self
                            .evt_tx
                            .send(NetworkEvent::IncomingCallSignal {
                                peer_id: peer,
                                signal: signal_type,
                            })
                            .await;
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, MessagePayload::Ack);
                        self.egui_ctx.request_repaint();
                    }
                    MessagePayload::CallAudioFrame {
                        sequence,
                        audio_data_hex,
                    } => {
                        if let Some(shared_secret) = self.shared_secrets.get(&peer) {
                            if let Ok(ciphertext) = hex::decode(&audio_data_hex) {
                                let nonce = [0u8; 16];
                                let mut cipher = CustomCipher::new(shared_secret, &nonce);
                                let decrypted_audio = cipher.decrypt(&ciphertext);
                                let _ = self
                                    .evt_tx
                                    .send(NetworkEvent::IncomingAudioFrame {
                                        peer_id: peer,
                                        sequence,
                                        audio_data: decrypted_audio,
                                    })
                                    .await;
                            }
                        }
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, MessagePayload::Ack);
                    }
                    _ => {}
                },
                request_response::Message::Response { response, .. } => match response {
                    MessagePayload::HandshakeResponse {
                        public_key_hex,
                        nonce_hex: _,
                        username,
                    } => {
                        if let Some(pending_secret) = self.pending_secrets.remove(&peer) {
                            let bob_pub_bytes = match hex::decode(&public_key_hex)
                                .map(|b| <[u8; 32]>::try_from(b))
                            {
                                Ok(Ok(bytes)) => bytes,
                                _ => {
                                    let _ = self
                                        .evt_tx
                                        .send(NetworkEvent::Log(
                                            "Response key conversion failed.".to_string(),
                                        ))
                                        .await;
                                    self.egui_ctx.request_repaint();
                                    return;
                                }
                            };
                            let bob_public = PublicKey::from(bob_pub_bytes);
                            let shared_secret = pending_secret.diffie_hellman(&bob_public);

                            self.shared_secrets.insert(peer, *shared_secret.as_bytes());

                            let _ = self
                                .evt_tx
                                .send(NetworkEvent::FriendUsername {
                                    peer_id: peer,
                                    username,
                                })
                                .await;
                            let _ = self
                                .evt_tx
                                .send(NetworkEvent::FriendStatus {
                                    peer_id: peer,
                                    status: FriendStatus::Secure,
                                })
                                .await;
                            let _ = self
                                .evt_tx
                                .send(NetworkEvent::Log(
                                    "Secure handshake finished. Cryptography active.".to_string(),
                                ))
                                .await;
                            self.egui_ctx.request_repaint();
                        }
                    }
                    _ => {}
                },
            },
            _ => {}
        }
    }
}
