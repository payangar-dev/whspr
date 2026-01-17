mod net;
mod state;
mod tui;

use crossterm::event::{KeyCode, KeyModifiers};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use net::Client;
use state::{AppState, Contact, Message};
use tui::{AppEvent, Tui};
use whspr_protocol::{
    Identity, Frame, MessageType,
    RegisterPayload, LookupUserPayload, SendPayload,
    encode_payload, decode_payload,
    AuthOkPayload, UserInfoPayload, ReceivePayload, PresencePayload,
    crypto::{RatchetSession, MessageHeader, x3dh_initiator},
};
use x25519_dalek::StaticSecret;
use rand::thread_rng;

const KEY_FILE: &str = ".whspr_key";

fn load_or_create_identity() -> Identity {
    let key_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(KEY_FILE);

    if key_path.exists() {
        if let Ok(data) = std::fs::read(&key_path) {
            if data.len() == 64 {
                let mut signing = [0u8; 32];
                let mut x25519 = [0u8; 32];
                signing.copy_from_slice(&data[..32]);
                x25519.copy_from_slice(&data[32..]);
                return Identity::from_bytes(signing, x25519);
            }
        }
    }

    let identity = Identity::generate();
    let (signing, x25519) = identity.to_bytes();
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&signing);
    data.extend_from_slice(&x25519);
    let _ = std::fs::write(&key_path, &data);

    identity
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup logging to file instead of stdout
    let log_file = std::fs::File::create("/tmp/whspr.log")?;
    FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .with_writer(log_file)
        .init();

    let identity = load_or_create_identity();
    let server_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());

    let mut state = AppState::new(identity, server_addr.clone());
    let mut client = Client::new()?;

    // Connect to server
    client.connect(server_addr.parse()?).await?;
    state.connected = true;

    // Register with server
    let register_payload = RegisterPayload {
        keys: state.identity.public_key_bundle(),
    };
    let frame = Frame::new(MessageType::Register, encode_payload(&register_payload)?)?;
    client.send_frame(frame).await?;

    // Wait for AuthOk
    if let Some(frame) = client.recv_frame().await? {
        if frame.msg_type == MessageType::AuthOk {
            let payload: AuthOkPayload = decode_payload(&frame.payload)?;
            state.username = payload.username;
        }
    }

    // Initialize TUI
    let mut tui = Tui::new()?;

    // Event channel
    let (event_tx, mut event_rx) = mpsc::channel(256);

    // Spawn event loop
    tokio::spawn(tui::run_event_loop(event_tx));

    // Main loop
    loop {
        tui.draw(&state)?;

        tokio::select! {
            Some(event) = event_rx.recv() => {
                match event {
                    AppEvent::Key(KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                    AppEvent::Key(KeyCode::Char('q'), KeyModifiers::CONTROL) => break,
                    AppEvent::Key(KeyCode::Enter, _) => {
                        handle_input(&mut state, &mut client).await?;
                    }
                    AppEvent::Key(KeyCode::Char(c), _) => {
                        state.input.push(c);
                    }
                    AppEvent::Key(KeyCode::Backspace, _) => {
                        state.input.pop();
                    }
                    AppEvent::Key(KeyCode::Tab, _) => {
                        // Cycle through conversations
                        let names: Vec<_> = state.conversations.keys().cloned().collect();
                        if !names.is_empty() {
                            let current_idx = state.active_conversation
                                .as_ref()
                                .and_then(|c| names.iter().position(|n| n == c))
                                .unwrap_or(0);
                            let next_idx = (current_idx + 1) % names.len();
                            state.select_conversation(&names[next_idx]);
                        }
                    }
                    _ => {}
                }
            }

            // Check for incoming messages (non-blocking)
            result = client.recv_frame() => {
                if let Ok(Some(frame)) = result {
                    handle_incoming_frame(&mut state, frame)?;
                }
            }
        }
    }

    Ok(())
}

async fn handle_input(state: &mut AppState, client: &mut Client) -> anyhow::Result<()> {
    let input = state.input.trim().to_string();
    state.input.clear();

    if input.is_empty() {
        return Ok(());
    }

    if input.starts_with('/') {
        // Handle commands
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        match parts[0] {
            "/add" if parts.len() == 2 => {
                let username = parts[1].trim();
                // Lookup user
                let payload = LookupUserPayload { username: username.to_string() };
                let frame = Frame::new(MessageType::LookupUser, encode_payload(&payload)?)?;
                client.send_frame(frame).await?;
            }
            "/quit" | "/q" => {
                std::process::exit(0);
            }
            _ => {}
        }
    } else if let Some(conv_name) = state.active_conversation.clone() {
        // Send message to active conversation
        let identity_secret = state.identity.x25519_secret().clone();
        if let Some(conv) = state.conversations.get_mut(&conv_name) {
            // If no ratchet, initialize one
            if conv.ratchet.is_none() {
                let ephemeral = StaticSecret::random_from_rng(thread_rng());
                let shared_secret = x3dh_initiator(
                    &identity_secret,
                    &ephemeral,
                    &conv.contact.keys.identity_key,
                    &conv.contact.keys.prekey,
                );
                conv.ratchet = Some(RatchetSession::init_alice(&shared_secret, conv.contact.keys.prekey));
            }

            let ratchet = conv.ratchet.as_mut().unwrap();
            let (header, ciphertext) = ratchet.encrypt(input.as_bytes()).map_err(|e| anyhow::anyhow!("{}", e))?;

            // Serialize header + ciphertext together
            let mut encrypted_payload = encode_payload(&header)?;
            encrypted_payload.extend(ciphertext);

            let payload = SendPayload {
                to: conv_name.clone(),
                ciphertext: encrypted_payload,
            };
            let frame = Frame::new(MessageType::Send, encode_payload(&payload)?)?;
            client.send_frame(frame).await?;

            // Add to local messages
            conv.add_message(Message {
                from: state.username.clone(),
                content: input,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                outgoing: true,
            });
        }
    }

    Ok(())
}

fn handle_incoming_frame(state: &mut AppState, frame: Frame) -> anyhow::Result<()> {
    match frame.msg_type {
        MessageType::UserInfo => {
            let payload: UserInfoPayload = decode_payload(&frame.payload)?;
            let contact = Contact {
                username: payload.username.clone(),
                keys: payload.keys,
                online: payload.online,
            };
            state.get_or_create_conversation(contact);
            state.select_conversation(&payload.username);
        }
        MessageType::UserNotFound => {
            // TODO: Show error in UI
        }
        MessageType::Receive => {
            let payload: ReceivePayload = decode_payload(&frame.payload)?;

            // Get or create conversation for sender
            if let Some(conv) = state.conversations.get_mut(&payload.from) {
                // Try to decrypt
                let content = if let Some(ratchet) = &mut conv.ratchet {
                    // Deserialize header from ciphertext prefix
                    // The header is MessagePack encoded, we need to figure out its length
                    // For simplicity, try to decode header and use remaining as ciphertext
                    if let Ok(header) = decode_payload::<MessageHeader>(&payload.ciphertext) {
                        // Find where header ends - encode header to find its serialized length
                        let header_bytes = encode_payload(&header).unwrap_or_default();
                        let ct = &payload.ciphertext[header_bytes.len()..];
                        ratchet.decrypt(&header, ct)
                            .map(|pt| String::from_utf8_lossy(&pt).to_string())
                            .unwrap_or_else(|_| "[decryption failed]".to_string())
                    } else {
                        String::from_utf8_lossy(&payload.ciphertext).to_string()
                    }
                } else {
                    // No ratchet yet - message is plaintext or we need to init as Bob
                    String::from_utf8_lossy(&payload.ciphertext).to_string()
                };

                conv.add_message(Message {
                    from: payload.from.clone(),
                    content,
                    timestamp: payload.timestamp,
                    outgoing: false,
                });
            }
        }
        MessageType::Presence => {
            let payload: PresencePayload = decode_payload(&frame.payload)?;
            if let Some(conv) = state.conversations.get_mut(&payload.username) {
                conv.contact.online = payload.online;
            }
        }
        _ => {}
    }
    Ok(())
}
