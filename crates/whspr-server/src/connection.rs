use bytes::BytesMut;
use quinn::Connection;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use whspr_protocol::{
    Frame, MessageType,
    RegisterPayload, LookupUserPayload, UserInfoPayload,
    SendPayload, ReceivePayload, PresencePayload, KeyExchangeData,
    decode_payload, encode_payload,
};

use crate::queue::MessageQueue;
use crate::session::SessionManager;
use crate::store::UserStore;

pub struct ConnectionHandler {
    conn: Connection,
    store: UserStore,
    sessions: SessionManager,
    queue: MessageQueue,
    username: Option<String>,
}

impl ConnectionHandler {
    pub fn new(
        conn: Connection,
        store: UserStore,
        sessions: SessionManager,
        queue: MessageQueue,
    ) -> Self {
        Self {
            conn,
            store,
            sessions,
            queue,
            username: None,
        }
    }

    pub async fn run(mut self) {
        // Create channel for outgoing messages
        let (tx, mut rx) = mpsc::channel::<Frame>(256);

        // Accept bidirectional stream
        let (send, recv) = match self.conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                error!("Failed to accept stream: {}", e);
                return;
            }
        };

        let (mut send, mut recv) = (send, recv);

        // Spawn task to handle outgoing messages
        let send_handle = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            while let Some(frame) = rx.recv().await {
                buf.clear();
                frame.encode(&mut buf);
                if send.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });

        // Handle incoming messages
        let mut buf = BytesMut::with_capacity(65536);
        loop {
            // Read data
            let mut chunk = [0u8; 4096];
            match recv.read(&mut chunk).await {
                Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(None) => break, // Stream closed
                Err(e) => {
                    warn!("Read error: {}", e);
                    break;
                }
            }

            // Process complete frames
            loop {
                match Frame::decode(&mut buf) {
                    Ok(Some(frame)) => {
                        if let Err(e) = self.handle_frame(frame, &tx).await {
                            error!("Frame handling error: {}", e);
                        }
                    }
                    Ok(None) => break, // Need more data
                    Err(e) => {
                        error!("Frame decode error: {}", e);
                        break;
                    }
                }
            }
        }

        // Cleanup
        if let Some(username) = &self.username {
            self.sessions.unregister(username).await;
            info!("User {} disconnected", username);

            // Broadcast offline presence
            self.broadcast_presence(username, false).await;
        }

        send_handle.abort();
    }

    async fn handle_frame(&mut self, frame: Frame, tx: &mpsc::Sender<Frame>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match frame.msg_type {
            MessageType::Register => {
                let payload: RegisterPayload = decode_payload(&frame.payload)?;
                self.handle_register(payload, tx).await?;
            }
            MessageType::LookupUser => {
                let payload: LookupUserPayload = decode_payload(&frame.payload)?;
                self.handle_lookup(payload, tx).await?;
            }
            MessageType::Send => {
                let payload: SendPayload = decode_payload(&frame.payload)?;
                self.handle_send(payload).await?;
            }
            _ => {
                warn!("Unhandled message type: {:?}", frame.msg_type);
            }
        }
        Ok(())
    }

    async fn handle_register(&mut self, payload: RegisterPayload, tx: &mpsc::Sender<Frame>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let username = whspr_protocol::derive_username(&payload.keys.identity_key);

        // Try to register or verify existing
        if !self.store.user_exists(&username).await? {
            self.store.register_user(
                &username,
                &payload.keys.identity_key,
                &payload.keys.prekey,
                &payload.keys.prekey_signature,
            ).await?;
            info!("Registered new user: {}", username);
        }

        // Register session
        self.sessions.register(username.clone(), tx.clone()).await;
        self.username = Some(username.clone());

        info!("User {} connected", username);

        // Send auth OK
        let response = Frame::new(
            MessageType::AuthOk,
            encode_payload(&whspr_protocol::AuthOkPayload { username: username.clone() })?,
        )?;
        tx.send(response).await?;

        // Deliver queued messages
        let queued = self.queue.drain(&username).await;
        for msg in queued {
            let key_exchange = msg.key_exchange.map(|(ik, ek)| KeyExchangeData {
                identity_key: ik.try_into().unwrap_or([0u8; 32]),
                ephemeral_key: ek.try_into().unwrap_or([0u8; 32]),
            });
            let receive_payload = ReceivePayload {
                from: msg.from,
                ciphertext: msg.ciphertext,
                timestamp: msg.timestamp,
                key_exchange,
            };
            let frame = Frame::new(MessageType::Receive, encode_payload(&receive_payload)?)?;
            tx.send(frame).await?;
        }

        // Broadcast online presence
        self.broadcast_presence(&username, true).await;

        Ok(())
    }

    async fn handle_lookup(&self, payload: LookupUserPayload, tx: &mpsc::Sender<Frame>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.store.get_user(&payload.username).await {
            Ok(user) => {
                let response = UserInfoPayload {
                    username: user.username,
                    keys: whspr_protocol::PublicKeyBundle {
                        identity_key: user.identity_key.try_into().unwrap_or([0u8; 32]),
                        prekey: user.prekey.try_into().unwrap_or([0u8; 32]),
                        prekey_signature: user.prekey_signature.try_into().unwrap_or([0u8; 64]),
                    },
                    online: self.sessions.is_online(&payload.username).await,
                };
                let frame = Frame::new(MessageType::UserInfo, encode_payload(&response)?)?;
                tx.send(frame).await?;
            }
            Err(_) => {
                let frame = Frame::new(MessageType::UserNotFound, vec![])?;
                tx.send(frame).await?;
            }
        }
        Ok(())
    }

    async fn handle_send(&self, payload: SendPayload) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(from) = &self.username else {
            return Ok(());
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Try to deliver directly if online
        if let Some(tx) = self.sessions.get(&payload.to).await {
            let receive_payload = ReceivePayload {
                from: from.clone(),
                ciphertext: payload.ciphertext.clone(),
                timestamp,
                key_exchange: payload.key_exchange.clone(),
            };
            let frame = Frame::new(MessageType::Receive, encode_payload(&receive_payload)?)?;
            let _ = tx.send(frame).await;
        } else {
            // Queue for later
            let key_exchange = payload.key_exchange.map(|ke| (ke.identity_key.to_vec(), ke.ephemeral_key.to_vec()));
            self.queue.enqueue(&payload.to, from.clone(), payload.ciphertext, timestamp, key_exchange).await;
        }

        Ok(())
    }

    async fn broadcast_presence(&self, username: &str, online: bool) {
        let presence = PresencePayload {
            username: username.to_string(),
            online,
        };

        if let Ok(payload) = encode_payload(&presence) {
            if let Ok(frame) = Frame::new(MessageType::Presence, payload) {
                for user in self.sessions.online_users().await {
                    if user != username {
                        if let Some(tx) = self.sessions.get(&user).await {
                            let _ = tx.send(frame.clone()).await;
                        }
                    }
                }
            }
        }
    }
}
