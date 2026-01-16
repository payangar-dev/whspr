# whspr Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an ephemeral, end-to-end encrypted terminal chat app with Double Ratchet encryption over QUIC.

**Architecture:** Client-Server with shared protocol crate. Server handles user registry (SQLite), message routing, and TTL-based queuing. Client provides multi-tab TUI with in-memory-only message history. All messages encrypted end-to-end with Double Ratchet; server sees only opaque blobs.

**Tech Stack:** Rust, quinn (QUIC), ratatui (TUI), x25519-dalek/ed25519-dalek (crypto), aes-gcm (symmetric), sqlx (SQLite), tokio (async), rmp-serde (MessagePack)

---

## Phase 1: Project Scaffold & Protocol Foundation

### Task 1: Initialize Cargo Workspace

**Files:**
- Create: `Cargo.toml`
- Create: `crates/whspr-protocol/Cargo.toml`
- Create: `crates/whspr-protocol/src/lib.rs`
- Create: `crates/whspr-server/Cargo.toml`
- Create: `crates/whspr-server/src/main.rs`
- Create: `crates/whspr-client/Cargo.toml`
- Create: `crates/whspr-client/src/main.rs`

**Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "crates/whspr-protocol",
    "crates/whspr-server",
    "crates/whspr-client",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
authors = ["Pierre"]

[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# QUIC
quinn = "0.11"
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }

# Crypto
x25519-dalek = { version = "2", features = ["static_secrets"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
aes-gcm = "0.10"
hkdf = "0.12"
sha2 = "0.10"
rand = "0.8"

# Serialization
rmp-serde = "1"
serde = { version = "1", features = ["derive"] }

# TUI
ratatui = "0.29"
crossterm = "0.28"

# Database
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite"] }

# Utilities
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
bytes = "1"
```

**Step 2: Create whspr-protocol crate**

`crates/whspr-protocol/Cargo.toml`:
```toml
[package]
name = "whspr-protocol"
version.workspace = true
edition.workspace = true

[dependencies]
serde.workspace = true
rmp-serde.workspace = true
thiserror.workspace = true
bytes.workspace = true
x25519-dalek.workspace = true
ed25519-dalek.workspace = true
aes-gcm.workspace = true
hkdf.workspace = true
sha2.workspace = true
rand.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["test-util", "macros"] }
```

`crates/whspr-protocol/src/lib.rs`:
```rust
pub mod message;
pub mod frame;
pub mod identity;
pub mod crypto;

pub use message::*;
pub use frame::*;
pub use identity::*;
```

**Step 3: Create whspr-server crate**

`crates/whspr-server/Cargo.toml`:
```toml
[package]
name = "whspr-server"
version.workspace = true
edition.workspace = true

[[bin]]
name = "whspr-server"
path = "src/main.rs"

[dependencies]
whspr-protocol = { path = "../whspr-protocol" }
tokio.workspace = true
quinn.workspace = true
rustls.workspace = true
sqlx.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
thiserror.workspace = true
```

`crates/whspr-server/src/main.rs`:
```rust
#[tokio::main]
async fn main() {
    println!("whspr-server starting...");
}
```

**Step 4: Create whspr-client crate**

`crates/whspr-client/Cargo.toml`:
```toml
[package]
name = "whspr-client"
version.workspace = true
edition.workspace = true

[[bin]]
name = "whspr"
path = "src/main.rs"

[dependencies]
whspr-protocol = { path = "../whspr-protocol" }
tokio.workspace = true
quinn.workspace = true
rustls.workspace = true
ratatui.workspace = true
crossterm.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
thiserror.workspace = true
```

`crates/whspr-client/src/main.rs`:
```rust
#[tokio::main]
async fn main() {
    println!("whspr client starting...");
}
```

**Step 5: Verify workspace compiles**

Run: `cargo build`
Expected: Compiles with no errors

**Step 6: Commit**

```bash
git add -A
git commit -m "feat: initialize cargo workspace with protocol, server, client crates"
```

---

### Task 2: Wire Framing (Protocol)

**Files:**
- Create: `crates/whspr-protocol/src/frame.rs`
- Test: `crates/whspr-protocol/src/frame.rs` (inline tests)

**Step 1: Write the failing test for frame encoding/decoding**

`crates/whspr-protocol/src/frame.rs`:
```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("incomplete frame, need more data")]
    Incomplete,
    #[error("payload too large: {0} bytes (max 65536)")]
    PayloadTooLarge(usize),
    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    // Auth
    Register = 0x01,
    Auth = 0x02,
    AuthOk = 0x03,
    AuthFail = 0x04,

    // User lookup
    LookupUser = 0x10,
    UserInfo = 0x11,
    UserNotFound = 0x12,

    // Messaging
    Send = 0x20,
    Receive = 0x21,
    Ack = 0x22,

    // Presence
    Presence = 0x30,

    // Groups
    GroupCreate = 0x40,
    GroupInvite = 0x41,
    GroupMsg = 0x42,
    GroupLeave = 0x43,
}

impl TryFrom<u8> for MessageType {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Register),
            0x02 => Ok(Self::Auth),
            0x03 => Ok(Self::AuthOk),
            0x04 => Ok(Self::AuthFail),
            0x10 => Ok(Self::LookupUser),
            0x11 => Ok(Self::UserInfo),
            0x12 => Ok(Self::UserNotFound),
            0x20 => Ok(Self::Send),
            0x21 => Ok(Self::Receive),
            0x22 => Ok(Self::Ack),
            0x30 => Ok(Self::Presence),
            0x40 => Ok(Self::GroupCreate),
            0x41 => Ok(Self::GroupInvite),
            0x42 => Ok(Self::GroupMsg),
            0x43 => Ok(Self::GroupLeave),
            _ => Err(FrameError::InvalidMessageType(value)),
        }
    }
}

/// Wire frame: [msg_type: 1][flags: 1][reserved: 2][length: 4][payload: N]
#[derive(Debug, Clone)]
pub struct Frame {
    pub msg_type: MessageType,
    pub flags: u8,
    pub payload: Bytes,
}

pub const HEADER_SIZE: usize = 8;
pub const MAX_PAYLOAD_SIZE: usize = 65536;

impl Frame {
    pub fn new(msg_type: MessageType, payload: impl Into<Bytes>) -> Result<Self, FrameError> {
        let payload = payload.into();
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge(payload.len()));
        }
        Ok(Self {
            msg_type,
            flags: 0,
            payload,
        })
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.msg_type as u8);
        buf.put_u8(self.flags);
        buf.put_u16(0); // reserved
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);
    }

    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>, FrameError> {
        if buf.len() < HEADER_SIZE {
            return Ok(None);
        }

        let length = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;

        if length > MAX_PAYLOAD_SIZE {
            return Err(FrameError::PayloadTooLarge(length));
        }

        let total_size = HEADER_SIZE + length;
        if buf.len() < total_size {
            return Ok(None);
        }

        let msg_type = MessageType::try_from(buf[0])?;
        let flags = buf[1];
        // skip reserved bytes [2..4]

        buf.advance(HEADER_SIZE);
        let payload = buf.split_to(length).freeze();

        Ok(Some(Self {
            msg_type,
            flags,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let original = Frame::new(MessageType::Send, b"hello world".to_vec()).unwrap();

        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let decoded = Frame::decode(&mut buf).unwrap().unwrap();

        assert_eq!(decoded.msg_type, MessageType::Send);
        assert_eq!(decoded.flags, 0);
        assert_eq!(&decoded.payload[..], b"hello world");
    }

    #[test]
    fn test_frame_incomplete() {
        let mut buf = BytesMut::from(&[0x01, 0x00, 0x00][..]);
        let result = Frame::decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_frame_payload_too_large() {
        let big_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = Frame::new(MessageType::Send, big_payload);
        assert!(matches!(result, Err(FrameError::PayloadTooLarge(_))));
    }

    #[test]
    fn test_invalid_message_type() {
        let mut buf = BytesMut::from(&[0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..]);
        let result = Frame::decode(&mut buf);
        assert!(matches!(result, Err(FrameError::InvalidMessageType(0xFF))));
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p whspr-protocol`
Expected: All tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(protocol): add wire frame encoding/decoding"
```

---

### Task 3: Message Types (Protocol)

**Files:**
- Create: `crates/whspr-protocol/src/message.rs`

**Step 1: Define message payload types with serde**

`crates/whspr-protocol/src/message.rs`:
```rust
use serde::{Deserialize, Serialize};

/// Public key bundle for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    /// Ed25519 identity public key (32 bytes)
    pub identity_key: [u8; 32],
    /// X25519 prekey for key exchange (32 bytes)
    pub prekey: [u8; 32],
    /// Signature of prekey by identity key (64 bytes)
    pub prekey_signature: [u8; 64],
}

/// Register request - sent when first connecting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub keys: PublicKeyBundle,
}

/// Auth challenge from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallengePayload {
    pub nonce: [u8; 32],
}

/// Auth response from client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub signature: [u8; 64],
}

/// Successful auth response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthOkPayload {
    pub username: String,
}

/// Lookup user request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupUserPayload {
    pub username: String,
}

/// User info response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfoPayload {
    pub username: String,
    pub keys: PublicKeyBundle,
    pub online: bool,
}

/// Encrypted message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPayload {
    pub to: String,
    pub ciphertext: Vec<u8>,
}

/// Incoming message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivePayload {
    pub from: String,
    pub ciphertext: Vec<u8>,
    pub timestamp: u64,
}

/// Message acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckPayload {
    pub message_id: [u8; 16],
}

/// Presence update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresencePayload {
    pub username: String,
    pub online: bool,
}

/// Group creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCreatePayload {
    pub group_id: [u8; 16],
    pub name: String,
    pub members: Vec<String>,
}

/// Group invite (contains encrypted sender key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInvitePayload {
    pub group_id: [u8; 16],
    pub group_name: String,
    pub from: String,
    pub encrypted_sender_key: Vec<u8>,
}

/// Encrypted group message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMsgPayload {
    pub group_id: [u8; 16],
    pub from: String,
    pub ciphertext: Vec<u8>,
    pub timestamp: u64,
}

/// Helper to encode/decode payloads with MessagePack
pub fn encode_payload<T: Serialize>(payload: &T) -> Result<Vec<u8>, rmp_serde::encode::Error> {
    rmp_serde::to_vec(payload)
}

pub fn decode_payload<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::from_slice(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_roundtrip() {
        let original = SendPayload {
            to: "brave-falcon".to_string(),
            ciphertext: vec![1, 2, 3, 4, 5],
        };

        let encoded = encode_payload(&original).unwrap();
        let decoded: SendPayload = decode_payload(&encoded).unwrap();

        assert_eq!(decoded.to, original.to);
        assert_eq!(decoded.ciphertext, original.ciphertext);
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p whspr-protocol`
Expected: All tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(protocol): add message payload types with MessagePack serialization"
```

---

### Task 4: Identity & Username Generation (Protocol)

**Files:**
- Create: `crates/whspr-protocol/src/identity.rs`
- Create: `wordlists/adjectives.txt`
- Create: `wordlists/animals.txt`

**Step 1: Create word lists**

`wordlists/adjectives.txt` (partial - expand to ~500):
```
brave
swift
quiet
bold
calm
clever
daring
eager
fierce
gentle
happy
jolly
keen
lively
mighty
noble
proud
quick
rapid
silent
steady
strong
subtle
tender
vivid
warm
wise
young
zealous
agile
alert
ample
ancient
azure
bitter
blazing
bright
bronze
cosmic
crimson
crystal
dapper
dusky
dusty
fading
faint
fancy
frozen
golden
grand
gray
hasty
hidden
hollow
humble
icy
iron
jade
jagged
jumpy
lanky
lazy
light
lunar
magic
marble
mellow
misty
modest
mossy
narrow
nimble
olive
orange
pastel
pearl
plush
polar
primal
rustic
salty
sandy
scarlet
shady
sharp
silver
sleek
slim
smoky
snowy
solar
spicy
stark
steep
stormy
sunny
tawny
tepid
tidal
tiny
topaz
tropic
turbo
ultra
urban
valid
velvet
violet
waxing
wavy
weary
whimsy
wild
windy
wispy
witty
woody
zany
zesty
```

`wordlists/animals.txt` (partial - expand to ~200):
```
falcon
wolf
otter
fox
bear
eagle
hawk
owl
tiger
lion
lynx
puma
crow
swan
heron
crane
finch
robin
wren
dove
raven
shark
whale
squid
crab
seal
trout
bass
pike
perch
salmon
cobra
viper
gecko
newt
toad
frog
turtle
horse
zebra
moose
elk
deer
bison
rhino
hippo
koala
panda
sloth
lemur
monkey
chimp
badger
ferret
mink
stoat
weasel
skunk
mole
shrew
mouse
rat
beaver
hare
rabbit
mantis
beetle
wasp
moth
ant
spider
scorpion
```

**Step 2: Implement identity module**

`crates/whspr-protocol/src/identity.rs`:
```rust
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use thiserror::Error;

use crate::message::PublicKeyBundle;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to generate keypair")]
    KeyGeneration,
    #[error("invalid signature")]
    InvalidSignature,
}

/// Word lists for username generation
const ADJECTIVES: &str = include_str!("../../../wordlists/adjectives.txt");
const ANIMALS: &str = include_str!("../../../wordlists/animals.txt");

/// User identity containing all key material
pub struct Identity {
    /// Ed25519 signing key (identity)
    signing_key: SigningKey,
    /// X25519 static secret (for key exchange)
    x25519_secret: StaticSecret,
    /// Derived username
    username: String,
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let x25519_secret = StaticSecret::random_from_rng(&mut OsRng);
        let username = derive_username(signing_key.verifying_key().as_bytes());

        Self {
            signing_key,
            x25519_secret,
            username,
        }
    }

    /// Load identity from raw key bytes
    pub fn from_bytes(signing_key_bytes: [u8; 32], x25519_bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let x25519_secret = StaticSecret::from(x25519_bytes);
        let username = derive_username(signing_key.verifying_key().as_bytes());

        Self {
            signing_key,
            x25519_secret,
            username,
        }
    }

    /// Export raw key bytes for storage
    pub fn to_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.signing_key.to_bytes(),
            self.x25519_secret.to_bytes(),
        )
    }

    /// Get the derived username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get identity public key (Ed25519)
    pub fn identity_public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get X25519 public key
    pub fn x25519_public_key(&self) -> [u8; 32] {
        X25519PublicKey::from(&self.x25519_secret).to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Create public key bundle for registration
    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        let prekey = self.x25519_public_key();
        let prekey_signature = self.sign(&prekey);

        PublicKeyBundle {
            identity_key: self.identity_public_key(),
            prekey,
            prekey_signature,
        }
    }

    /// Get X25519 secret for key exchange
    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x25519_secret
    }
}

/// Derive a deterministic username from a public key
pub fn derive_username(pubkey: &[u8; 32]) -> String {
    let adjectives: Vec<&str> = ADJECTIVES.lines().filter(|l| !l.is_empty()).collect();
    let animals: Vec<&str> = ANIMALS.lines().filter(|l| !l.is_empty()).collect();

    let hash = Sha256::digest(pubkey);

    // Use first 2 bytes for adjective, next 2 for animal
    let adj_idx = u16::from_be_bytes([hash[0], hash[1]]) as usize % adjectives.len();
    let animal_idx = u16::from_be_bytes([hash[2], hash[3]]) as usize % animals.len();

    format!("{}-{}", adjectives[adj_idx], animals[animal_idx])
}

/// Verify a signature against a public key
pub fn verify_signature(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig) = Signature::from_bytes(signature) else {
        return false;
    };
    verifying_key.verify_strict(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate();
        assert!(!identity.username().is_empty());
        assert!(identity.username().contains('-'));
    }

    #[test]
    fn test_username_deterministic() {
        let identity = Identity::generate();
        let pubkey = identity.identity_public_key();

        let name1 = derive_username(&pubkey);
        let name2 = derive_username(&pubkey);

        assert_eq!(name1, name2);
    }

    #[test]
    fn test_signature_roundtrip() {
        let identity = Identity::generate();
        let message = b"hello world";

        let signature = identity.sign(message);
        let pubkey = identity.identity_public_key();

        assert!(verify_signature(&pubkey, message, &signature));
    }

    #[test]
    fn test_identity_serialization() {
        let identity = Identity::generate();
        let (signing_bytes, x25519_bytes) = identity.to_bytes();

        let restored = Identity::from_bytes(signing_bytes, x25519_bytes);

        assert_eq!(identity.username(), restored.username());
        assert_eq!(identity.identity_public_key(), restored.identity_public_key());
    }

    #[test]
    fn test_public_key_bundle() {
        let identity = Identity::generate();
        let bundle = identity.public_key_bundle();

        // Verify prekey signature
        assert!(verify_signature(
            &bundle.identity_key,
            &bundle.prekey,
            &bundle.prekey_signature
        ));
    }
}
```

**Step 3: Update lib.rs exports**

Ensure `crates/whspr-protocol/src/lib.rs` has:
```rust
pub mod message;
pub mod frame;
pub mod identity;
pub mod crypto;

pub use message::*;
pub use frame::*;
pub use identity::*;
```

**Step 4: Run tests**

Run: `cargo test -p whspr-protocol`
Expected: All tests pass

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(protocol): add identity generation with deterministic usernames"
```

---

### Task 5: Double Ratchet Crypto (Protocol)

**Files:**
- Create: `crates/whspr-protocol/src/crypto.rs`

**Step 1: Implement Double Ratchet**

`crates/whspr-protocol/src/crypto.rs`:
```rust
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use rand::RngCore;
use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("invalid key")]
    InvalidKey,
    #[error("ratchet state mismatch")]
    RatchetMismatch,
}

const INFO_ROOT: &[u8] = b"whspr-root";
const INFO_CHAIN: &[u8] = b"whspr-chain";
const INFO_MESSAGE: &[u8] = b"whspr-message";

/// Derive keys using HKDF
fn hkdf_derive(input_key: &[u8], salt: &[u8], info: &[u8], output: &mut [u8]) {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key);
    hkdf.expand(info, output).expect("HKDF expand failed");
}

/// Encrypt with AES-256-GCM
fn encrypt_aes_gcm(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

/// Decrypt with AES-256-GCM
fn decrypt_aes_gcm(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Message header containing ratchet public key and counters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Current ratchet public key
    pub ratchet_key: [u8; 32],
    /// Previous chain message count
    pub prev_chain_count: u32,
    /// Current message number in chain
    pub message_num: u32,
}

/// Double Ratchet session state
#[derive(Clone)]
pub struct RatchetSession {
    /// Root key
    root_key: [u8; 32],
    /// Our current ratchet keypair
    our_ratchet_secret: StaticSecret,
    our_ratchet_public: PublicKey,
    /// Their current ratchet public key
    their_ratchet_key: Option<PublicKey>,
    /// Sending chain key
    send_chain_key: Option<[u8; 32]>,
    /// Receiving chain key
    recv_chain_key: Option<[u8; 32]>,
    /// Message counters
    send_count: u32,
    recv_count: u32,
    prev_send_count: u32,
}

impl RatchetSession {
    /// Initialize a session as the initiator (Alice)
    pub fn init_alice(shared_secret: &[u8], their_ratchet_key: [u8; 32]) -> Self {
        let mut root_key = [0u8; 32];
        hkdf_derive(shared_secret, &[], INFO_ROOT, &mut root_key);

        let our_ratchet_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let our_ratchet_public = PublicKey::from(&our_ratchet_secret);
        let their_ratchet_key = PublicKey::from(their_ratchet_key);

        // Perform initial DH ratchet
        let dh_output = our_ratchet_secret.diffie_hellman(&their_ratchet_key);

        let mut new_root_key = [0u8; 32];
        let mut send_chain_key = [0u8; 32];
        let mut kdf_output = [0u8; 64];
        hkdf_derive(dh_output.as_bytes(), &root_key, INFO_ROOT, &mut kdf_output);
        new_root_key.copy_from_slice(&kdf_output[..32]);
        send_chain_key.copy_from_slice(&kdf_output[32..]);

        Self {
            root_key: new_root_key,
            our_ratchet_secret,
            our_ratchet_public,
            their_ratchet_key: Some(their_ratchet_key),
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
        }
    }

    /// Initialize a session as the responder (Bob)
    pub fn init_bob(shared_secret: &[u8], our_ratchet_secret: StaticSecret) -> Self {
        let mut root_key = [0u8; 32];
        hkdf_derive(shared_secret, &[], INFO_ROOT, &mut root_key);

        let our_ratchet_public = PublicKey::from(&our_ratchet_secret);

        Self {
            root_key,
            our_ratchet_secret,
            our_ratchet_public,
            their_ratchet_key: None,
            send_chain_key: None,
            recv_chain_key: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
        }
    }

    /// Get our current ratchet public key
    pub fn our_ratchet_public_key(&self) -> [u8; 32] {
        self.our_ratchet_public.to_bytes()
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(MessageHeader, Vec<u8>), CryptoError> {
        let send_chain_key = self.send_chain_key.ok_or(CryptoError::RatchetMismatch)?;

        // Derive message key from chain key
        let mut message_key = [0u8; 32];
        let mut new_chain_key = [0u8; 32];
        hkdf_derive(&send_chain_key, &[], INFO_MESSAGE, &mut message_key);
        hkdf_derive(&send_chain_key, &[], INFO_CHAIN, &mut new_chain_key);

        self.send_chain_key = Some(new_chain_key);

        let header = MessageHeader {
            ratchet_key: self.our_ratchet_public.to_bytes(),
            prev_chain_count: self.prev_send_count,
            message_num: self.send_count,
        };

        self.send_count += 1;

        let ciphertext = encrypt_aes_gcm(&message_key, plaintext)?;

        Ok((header, ciphertext))
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, header: &MessageHeader, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let their_key = PublicKey::from(header.ratchet_key);

        // Check if we need to perform a DH ratchet
        let need_ratchet = self.their_ratchet_key
            .map(|k| k.to_bytes() != header.ratchet_key)
            .unwrap_or(true);

        if need_ratchet {
            self.dh_ratchet(their_key)?;
        }

        let recv_chain_key = self.recv_chain_key.ok_or(CryptoError::RatchetMismatch)?;

        // Derive message key (skip forward if needed)
        let mut current_chain_key = recv_chain_key;
        for _ in self.recv_count..header.message_num {
            let mut new_chain_key = [0u8; 32];
            hkdf_derive(&current_chain_key, &[], INFO_CHAIN, &mut new_chain_key);
            current_chain_key = new_chain_key;
        }

        let mut message_key = [0u8; 32];
        hkdf_derive(&current_chain_key, &[], INFO_MESSAGE, &mut message_key);

        let mut new_chain_key = [0u8; 32];
        hkdf_derive(&current_chain_key, &[], INFO_CHAIN, &mut new_chain_key);
        self.recv_chain_key = Some(new_chain_key);
        self.recv_count = header.message_num + 1;

        decrypt_aes_gcm(&message_key, ciphertext)
    }

    /// Perform a DH ratchet step
    fn dh_ratchet(&mut self, their_key: PublicKey) -> Result<(), CryptoError> {
        self.their_ratchet_key = Some(their_key);
        self.prev_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;

        // Calculate receiving chain
        let dh_recv = self.our_ratchet_secret.diffie_hellman(&their_key);
        let mut kdf_output = [0u8; 64];
        hkdf_derive(dh_recv.as_bytes(), &self.root_key, INFO_ROOT, &mut kdf_output);
        self.root_key.copy_from_slice(&kdf_output[..32]);
        let mut recv_chain = [0u8; 32];
        recv_chain.copy_from_slice(&kdf_output[32..]);
        self.recv_chain_key = Some(recv_chain);

        // Generate new ratchet keypair and calculate sending chain
        self.our_ratchet_secret = StaticSecret::random_from_rng(rand::thread_rng());
        self.our_ratchet_public = PublicKey::from(&self.our_ratchet_secret);

        let dh_send = self.our_ratchet_secret.diffie_hellman(&their_key);
        hkdf_derive(dh_send.as_bytes(), &self.root_key, INFO_ROOT, &mut kdf_output);
        self.root_key.copy_from_slice(&kdf_output[..32]);
        let mut send_chain = [0u8; 32];
        send_chain.copy_from_slice(&kdf_output[32..]);
        self.send_chain_key = Some(send_chain);

        Ok(())
    }
}

/// X3DH initial key exchange (simplified version)
pub fn x3dh_initiator(
    our_identity_secret: &StaticSecret,
    our_ephemeral_secret: &StaticSecret,
    their_identity_key: &[u8; 32],
    their_prekey: &[u8; 32],
) -> [u8; 32] {
    let their_identity = PublicKey::from(*their_identity_key);
    let their_prekey = PublicKey::from(*their_prekey);

    // DH1 = DH(our_identity, their_prekey)
    let dh1 = our_identity_secret.diffie_hellman(&their_prekey);
    // DH2 = DH(our_ephemeral, their_identity)
    let dh2 = our_ephemeral_secret.diffie_hellman(&their_identity);
    // DH3 = DH(our_ephemeral, their_prekey)
    let dh3 = our_ephemeral_secret.diffie_hellman(&their_prekey);

    // Combine all DH outputs
    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(dh1.as_bytes());
    combined.extend_from_slice(dh2.as_bytes());
    combined.extend_from_slice(dh3.as_bytes());

    let mut shared_secret = [0u8; 32];
    hkdf_derive(&combined, &[], b"whspr-x3dh", &mut shared_secret);
    shared_secret
}

/// X3DH responder side
pub fn x3dh_responder(
    our_identity_secret: &StaticSecret,
    our_prekey_secret: &StaticSecret,
    their_identity_key: &[u8; 32],
    their_ephemeral_key: &[u8; 32],
) -> [u8; 32] {
    let their_identity = PublicKey::from(*their_identity_key);
    let their_ephemeral = PublicKey::from(*their_ephemeral_key);

    // DH1 = DH(our_prekey, their_identity)
    let dh1 = our_prekey_secret.diffie_hellman(&their_identity);
    // DH2 = DH(our_identity, their_ephemeral)
    let dh2 = our_identity_secret.diffie_hellman(&their_ephemeral);
    // DH3 = DH(our_prekey, their_ephemeral)
    let dh3 = our_prekey_secret.diffie_hellman(&their_ephemeral);

    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(dh1.as_bytes());
    combined.extend_from_slice(dh2.as_bytes());
    combined.extend_from_slice(dh3.as_bytes());

    let mut shared_secret = [0u8; 32];
    hkdf_derive(&combined, &[], b"whspr-x3dh", &mut shared_secret);
    shared_secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0u8; 32];
        let plaintext = b"hello world";

        let ciphertext = encrypt_aes_gcm(&key, plaintext).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_x3dh_shared_secret() {
        // Alice's keys
        let alice_identity = StaticSecret::random_from_rng(rand::thread_rng());
        let alice_ephemeral = StaticSecret::random_from_rng(rand::thread_rng());
        let alice_identity_pub = PublicKey::from(&alice_identity).to_bytes();
        let alice_ephemeral_pub = PublicKey::from(&alice_ephemeral).to_bytes();

        // Bob's keys
        let bob_identity = StaticSecret::random_from_rng(rand::thread_rng());
        let bob_prekey = StaticSecret::random_from_rng(rand::thread_rng());
        let bob_identity_pub = PublicKey::from(&bob_identity).to_bytes();
        let bob_prekey_pub = PublicKey::from(&bob_prekey).to_bytes();

        // Both sides compute shared secret
        let alice_secret = x3dh_initiator(
            &alice_identity,
            &alice_ephemeral,
            &bob_identity_pub,
            &bob_prekey_pub,
        );

        let bob_secret = x3dh_responder(
            &bob_identity,
            &bob_prekey,
            &alice_identity_pub,
            &alice_ephemeral_pub,
        );

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_double_ratchet_conversation() {
        // Setup shared secret (normally from X3DH)
        let shared_secret = [42u8; 32];

        // Bob generates his ratchet keypair
        let bob_ratchet_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let bob_ratchet_pub = PublicKey::from(&bob_ratchet_secret).to_bytes();

        // Initialize sessions
        let mut alice = RatchetSession::init_alice(&shared_secret, bob_ratchet_pub);
        let mut bob = RatchetSession::init_bob(&shared_secret, bob_ratchet_secret);

        // Alice sends first message
        let (header1, ct1) = alice.encrypt(b"Hello Bob!").unwrap();
        let pt1 = bob.decrypt(&header1, &ct1).unwrap();
        assert_eq!(&pt1, b"Hello Bob!");

        // Bob replies
        let (header2, ct2) = bob.encrypt(b"Hi Alice!").unwrap();
        let pt2 = alice.decrypt(&header2, &ct2).unwrap();
        assert_eq!(&pt2, b"Hi Alice!");

        // Alice sends another
        let (header3, ct3) = alice.encrypt(b"How are you?").unwrap();
        let pt3 = bob.decrypt(&header3, &ct3).unwrap();
        assert_eq!(&pt3, b"How are you?");
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p whspr-protocol`
Expected: All tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(protocol): add Double Ratchet and X3DH crypto"
```

---

## Phase 2: Server Implementation

### Task 6: Basic QUIC Server

**Files:**
- Create: `crates/whspr-server/src/config.rs`
- Modify: `crates/whspr-server/src/main.rs`

**Step 1: Add rcgen for cert generation**

Add to `crates/whspr-server/Cargo.toml`:
```toml
rcgen = "0.13"
```

**Step 2: Implement config and basic server**

`crates/whspr-server/src/config.rs`:
```rust
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub message_ttl_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:4433".parse().unwrap(),
            message_ttl_secs: 86400, // 24 hours
        }
    }
}
```

`crates/whspr-server/src/main.rs`:
```rust
mod config;

use config::ServerConfig;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate certificate");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    (vec![cert_der], key_der)
}

fn configure_server() -> QuinnServerConfig {
    let (certs, key) = generate_self_signed_cert();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to create TLS config");

    server_crypto.alpn_protocols = vec![b"whspr".to_vec()];

    QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .expect("Failed to create QUIC config")
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .init();

    let config = ServerConfig::default();
    let server_config = configure_server();

    let endpoint = Endpoint::server(server_config, config.listen_addr)?;

    info!("whspr-server listening on {}", config.listen_addr);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    info!("New connection from {}", connection.remote_address());
                    // TODO: Handle connection
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}
```

**Step 3: Add anyhow dependency**

Add to `crates/whspr-server/Cargo.toml`:
```toml
anyhow = "1"
rcgen = "0.13"
```

**Step 4: Build and verify**

Run: `cargo build -p whspr-server`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(server): add basic QUIC server with self-signed cert"
```

---

### Task 7: User Store (SQLite)

**Files:**
- Create: `crates/whspr-server/src/store.rs`

**Step 1: Implement user store**

`crates/whspr-server/src/store.rs`:
```rust
use sqlx::{sqlite::SqlitePool, FromRow};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("user already exists: {0}")]
    UserAlreadyExists(String),
}

#[derive(Debug, Clone, FromRow)]
pub struct StoredUser {
    pub username: String,
    pub identity_key: Vec<u8>,
    pub prekey: Vec<u8>,
    pub prekey_signature: Vec<u8>,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct UserStore {
    pool: SqlitePool,
}

impl UserStore {
    pub async fn new(database_url: &str) -> Result<Self, StoreError> {
        let pool = SqlitePool::connect(database_url).await?;

        // Run migrations
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                identity_key BLOB NOT NULL,
                prekey BLOB NOT NULL,
                prekey_signature BLOB NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    pub async fn register_user(
        &self,
        username: &str,
        identity_key: &[u8],
        prekey: &[u8],
        prekey_signature: &[u8],
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO users (username, identity_key, prekey, prekey_signature) VALUES (?, ?, ?, ?)"
        )
        .bind(username)
        .bind(identity_key)
        .bind(prekey)
        .bind(prekey_signature)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                Err(StoreError::UserAlreadyExists(username.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get_user(&self, username: &str) -> Result<StoredUser, StoreError> {
        sqlx::query_as::<_, StoredUser>(
            "SELECT username, identity_key, prekey, prekey_signature, created_at FROM users WHERE username = ?"
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::UserNotFound(username.to_string()))
    }

    pub async fn user_exists(&self, username: &str) -> Result<bool, StoreError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0 > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_registration() {
        let store = UserStore::new("sqlite::memory:").await.unwrap();

        let identity_key = [1u8; 32];
        let prekey = [2u8; 32];
        let signature = [3u8; 64];

        store
            .register_user("brave-falcon", &identity_key, &prekey, &signature)
            .await
            .unwrap();

        let user = store.get_user("brave-falcon").await.unwrap();
        assert_eq!(user.username, "brave-falcon");
        assert_eq!(user.identity_key, identity_key);
    }

    #[tokio::test]
    async fn test_duplicate_user() {
        let store = UserStore::new("sqlite::memory:").await.unwrap();

        store
            .register_user("brave-falcon", &[1u8; 32], &[2u8; 32], &[3u8; 64])
            .await
            .unwrap();

        let result = store
            .register_user("brave-falcon", &[1u8; 32], &[2u8; 32], &[3u8; 64])
            .await;

        assert!(matches!(result, Err(StoreError::UserAlreadyExists(_))));
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p whspr-server`
Expected: All tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(server): add SQLite user store"
```

---

### Task 8: Session Manager & Message Queue

**Files:**
- Create: `crates/whspr-server/src/session.rs`
- Create: `crates/whspr-server/src/queue.rs`

**Step 1: Implement session manager**

`crates/whspr-server/src/session.rs`:
```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use whspr_protocol::Frame;

pub type MessageSender = mpsc::Sender<Frame>;

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, MessageSender>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, username: String, sender: MessageSender) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(username, sender);
    }

    pub async fn unregister(&self, username: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(username);
    }

    pub async fn get(&self, username: &str) -> Option<MessageSender> {
        let sessions = self.sessions.read().await;
        sessions.get(username).cloned()
    }

    pub async fn is_online(&self, username: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(username)
    }

    pub async fn online_users(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
```

**Step 2: Implement message queue with TTL**

`crates/whspr-server/src/queue.rs`:
```rust
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub from: String,
    pub ciphertext: Vec<u8>,
    pub timestamp: u64,
    queued_at: Instant,
}

#[derive(Clone)]
pub struct MessageQueue {
    queues: Arc<RwLock<HashMap<String, VecDeque<QueuedMessage>>>>,
    ttl: Duration,
}

impl MessageQueue {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            queues: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub async fn enqueue(&self, to: &str, from: String, ciphertext: Vec<u8>, timestamp: u64) {
        let mut queues = self.queues.write().await;
        let queue = queues.entry(to.to_string()).or_default();

        queue.push_back(QueuedMessage {
            from,
            ciphertext,
            timestamp,
            queued_at: Instant::now(),
        });
    }

    pub async fn drain(&self, username: &str) -> Vec<QueuedMessage> {
        let mut queues = self.queues.write().await;
        let Some(queue) = queues.get_mut(username) else {
            return Vec::new();
        };

        let now = Instant::now();

        // Filter out expired messages and drain the rest
        let messages: Vec<_> = queue
            .drain(..)
            .filter(|msg| now.duration_since(msg.queued_at) < self.ttl)
            .collect();

        messages
    }

    pub async fn cleanup_expired(&self) {
        let mut queues = self.queues.write().await;
        let now = Instant::now();

        for queue in queues.values_mut() {
            queue.retain(|msg| now.duration_since(msg.queued_at) < self.ttl);
        }

        // Remove empty queues
        queues.retain(|_, q| !q.is_empty());
    }

    pub async fn pending_count(&self, username: &str) -> usize {
        let queues = self.queues.read().await;
        queues.get(username).map(|q| q.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enqueue_and_drain() {
        let queue = MessageQueue::new(3600);

        queue.enqueue("alice", "bob".to_string(), vec![1, 2, 3], 12345).await;
        queue.enqueue("alice", "carol".to_string(), vec![4, 5, 6], 12346).await;

        let messages = queue.drain("alice").await;
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].from, "bob");
        assert_eq!(messages[1].from, "carol");

        // Queue should be empty after drain
        let messages = queue.drain("alice").await;
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let queue = MessageQueue::new(0); // 0 second TTL = immediate expiry

        queue.enqueue("alice", "bob".to_string(), vec![1, 2, 3], 12345).await;

        // Small delay to ensure expiry
        tokio::time::sleep(Duration::from_millis(10)).await;

        let messages = queue.drain("alice").await;
        assert!(messages.is_empty());
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p whspr-server`
Expected: All tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(server): add session manager and TTL message queue"
```

---

### Task 9: Connection Handler

**Files:**
- Create: `crates/whspr-server/src/connection.rs`
- Modify: `crates/whspr-server/src/main.rs`

**Step 1: Implement connection handler**

`crates/whspr-server/src/connection.rs`:
```rust
use bytes::BytesMut;
use quinn::{Connection, RecvStream, SendStream};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use whspr_protocol::{
    Frame, FrameError, MessageType,
    RegisterPayload, LookupUserPayload, UserInfoPayload,
    SendPayload, ReceivePayload, PresencePayload,
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
            let receive_payload = ReceivePayload {
                from: msg.from,
                ciphertext: msg.ciphertext,
                timestamp: msg.timestamp,
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
            };
            let frame = Frame::new(MessageType::Receive, encode_payload(&receive_payload)?)?;
            let _ = tx.send(frame).await;
        } else {
            // Queue for later
            self.queue.enqueue(&payload.to, from.clone(), payload.ciphertext, timestamp).await;
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
```

**Step 2: Update main.rs to use connection handler**

`crates/whspr-server/src/main.rs`:
```rust
mod config;
mod connection;
mod queue;
mod session;
mod store;

use config::ServerConfig;
use connection::ConnectionHandler;
use queue::MessageQueue;
use session::SessionManager;
use store::UserStore;

use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate certificate");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    (vec![cert_der], key_der)
}

fn configure_server() -> QuinnServerConfig {
    let (certs, key) = generate_self_signed_cert();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to create TLS config");

    server_crypto.alpn_protocols = vec![b"whspr".to_vec()];

    QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .expect("Failed to create QUIC config")
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .init();

    let config = ServerConfig::default();
    let server_config = configure_server();

    // Initialize stores
    let store = UserStore::new("sqlite:whspr.db?mode=rwc").await?;
    let sessions = SessionManager::new();
    let queue = MessageQueue::new(config.message_ttl_secs);

    // Start cleanup task
    let queue_cleanup = queue.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            queue_cleanup.cleanup_expired().await;
        }
    });

    let endpoint = Endpoint::server(server_config, config.listen_addr)?;

    info!("whspr-server listening on {}", config.listen_addr);

    while let Some(incoming) = endpoint.accept().await {
        let store = store.clone();
        let sessions = sessions.clone();
        let queue = queue.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    info!("New connection from {}", connection.remote_address());
                    let handler = ConnectionHandler::new(connection, store, sessions, queue);
                    handler.run().await;
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}
```

**Step 3: Build and verify**

Run: `cargo build -p whspr-server`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(server): add connection handler with full message routing"
```

---

## Phase 3: Client Implementation

### Task 10: QUIC Client Connection

**Files:**
- Create: `crates/whspr-client/src/net.rs`

**Step 1: Implement QUIC client**

`crates/whspr-client/src/net.rs`:
```rust
use bytes::BytesMut;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error};

use whspr_protocol::{Frame, decode_payload, encode_payload};

pub struct Client {
    endpoint: Endpoint,
    connection: Option<Connection>,
    send: Option<SendStream>,
    recv: Option<RecvStream>,
}

impl Client {
    pub fn new() -> anyhow::Result<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

        // Configure client to accept self-signed certs (dev only)
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        ));

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        client_config.transport_config(Arc::new(transport));

        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            connection: None,
            send: None,
            recv: None,
        })
    }

    pub async fn connect(&mut self, addr: SocketAddr) -> anyhow::Result<()> {
        let connection = self.endpoint.connect(addr, "localhost")?.await?;
        info!("Connected to server at {}", addr);

        let (send, recv) = connection.open_bi().await?;

        self.connection = Some(connection);
        self.send = Some(send);
        self.recv = Some(recv);

        Ok(())
    }

    pub async fn send_frame(&mut self, frame: Frame) -> anyhow::Result<()> {
        let send = self.send.as_mut().ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        send.write_all(&buf).await?;

        Ok(())
    }

    pub async fn recv_frame(&mut self) -> anyhow::Result<Option<Frame>> {
        let recv = self.recv.as_mut().ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        let mut buf = BytesMut::with_capacity(65536);
        let mut chunk = [0u8; 4096];

        loop {
            // Try to decode a frame from existing buffer
            if let Some(frame) = Frame::decode(&mut buf)? {
                return Ok(Some(frame));
            }

            // Need more data
            match recv.read(&mut chunk).await? {
                Some(n) => buf.extend_from_slice(&chunk[..n]),
                None => return Ok(None),
            }
        }
    }
}

// Skip certificate verification for development
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
```

**Step 2: Add anyhow to client**

Add to `crates/whspr-client/Cargo.toml`:
```toml
anyhow = "1"
```

**Step 3: Build and verify**

Run: `cargo build -p whspr-client`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(client): add QUIC client connection"
```

---

### Task 11: App State Management

**Files:**
- Create: `crates/whspr-client/src/state.rs`

**Step 1: Implement app state**

`crates/whspr-client/src/state.rs`:
```rust
use std::collections::HashMap;
use whspr_protocol::{Identity, PublicKeyBundle, RatchetSession};

#[derive(Debug, Clone)]
pub struct Message {
    pub from: String,
    pub content: String,
    pub timestamp: u64,
    pub outgoing: bool,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub username: String,
    pub keys: PublicKeyBundle,
    pub online: bool,
}

pub struct Conversation {
    pub contact: Contact,
    pub messages: Vec<Message>,
    pub ratchet: Option<RatchetSession>,
    pub unread: usize,
}

impl Conversation {
    pub fn new(contact: Contact) -> Self {
        Self {
            contact,
            messages: Vec::new(),
            ratchet: None,
            unread: 0,
        }
    }

    pub fn add_message(&mut self, msg: Message) {
        if !msg.outgoing {
            self.unread += 1;
        }
        self.messages.push(msg);
    }

    pub fn mark_read(&mut self) {
        self.unread = 0;
    }
}

pub struct AppState {
    pub identity: Identity,
    pub username: String,
    pub conversations: HashMap<String, Conversation>,
    pub active_conversation: Option<String>,
    pub input: String,
    pub server_addr: String,
    pub connected: bool,
}

impl AppState {
    pub fn new(identity: Identity, server_addr: String) -> Self {
        let username = identity.username().to_string();
        Self {
            identity,
            username,
            conversations: HashMap::new(),
            active_conversation: None,
            input: String::new(),
            server_addr,
            connected: false,
        }
    }

    pub fn get_or_create_conversation(&mut self, contact: Contact) -> &mut Conversation {
        let username = contact.username.clone();
        self.conversations.entry(username.clone())
            .or_insert_with(|| Conversation::new(contact))
    }

    pub fn active_conversation(&self) -> Option<&Conversation> {
        self.active_conversation.as_ref()
            .and_then(|name| self.conversations.get(name))
    }

    pub fn active_conversation_mut(&mut self) -> Option<&mut Conversation> {
        let name = self.active_conversation.clone()?;
        self.conversations.get_mut(&name)
    }

    pub fn select_conversation(&mut self, username: &str) {
        if self.conversations.contains_key(username) {
            self.active_conversation = Some(username.to_string());
            if let Some(conv) = self.conversations.get_mut(username) {
                conv.mark_read();
            }
        }
    }

    pub fn conversation_list(&self) -> Vec<(&String, &Conversation)> {
        let mut list: Vec<_> = self.conversations.iter().collect();
        // Sort by most recent message
        list.sort_by(|a, b| {
            let a_time = a.1.messages.last().map(|m| m.timestamp).unwrap_or(0);
            let b_time = b.1.messages.last().map(|m| m.timestamp).unwrap_or(0);
            b_time.cmp(&a_time)
        });
        list
    }

    pub fn total_unread(&self) -> usize {
        self.conversations.values().map(|c| c.unread).sum()
    }
}
```

**Step 2: Build and verify**

Run: `cargo build -p whspr-client`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(client): add app state management"
```

---

### Task 12: Basic TUI Shell

**Files:**
- Create: `crates/whspr-client/src/tui/mod.rs`
- Create: `crates/whspr-client/src/tui/ui.rs`
- Modify: `crates/whspr-client/src/main.rs`

**Step 1: Create TUI module**

`crates/whspr-client/src/tui/mod.rs`:
```rust
pub mod ui;

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Stdout};
use tokio::sync::mpsc;

use crate::state::AppState;

pub enum AppEvent {
    Key(KeyCode, KeyModifiers),
    Tick,
    Quit,
}

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn draw(&mut self, state: &AppState) -> io::Result<()> {
        self.terminal.draw(|frame| {
            ui::render(frame, state);
        })?;
        Ok(())
    }

    pub fn restore(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub async fn run_event_loop(tx: mpsc::Sender<AppEvent>) {
    let tick_rate = std::time::Duration::from_millis(100);

    loop {
        if event::poll(tick_rate).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if tx.send(AppEvent::Key(key.code, key.modifiers)).await.is_err() {
                    break;
                }
            }
        } else {
            if tx.send(AppEvent::Tick).await.is_err() {
                break;
            }
        }
    }
}
```

**Step 2: Create UI rendering**

`crates/whspr-client/src/tui/ui.rs`:
```rust
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::state::AppState;

pub fn render(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(25), Constraint::Min(0)])
        .split(frame.area());

    render_sidebar(frame, state, chunks[0]);
    render_main(frame, state, chunks[1]);
}

fn render_sidebar(frame: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // User info
    let status = if state.connected { "● online" } else { "○ offline" };
    let user_block = Block::default()
        .title(format!(" {} ", state.username))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let user_text = Paragraph::new(status)
        .style(Style::default().fg(if state.connected { Color::Green } else { Color::Red }))
        .block(user_block);
    frame.render_widget(user_text, chunks[0]);

    // Conversation list
    let conversations: Vec<ListItem> = state
        .conversation_list()
        .iter()
        .map(|(name, conv)| {
            let style = if Some(name.as_str()) == state.active_conversation.as_deref() {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let prefix = if conv.contact.online { "●" } else { "○" };
            let unread = if conv.unread > 0 {
                format!(" ({})", conv.unread)
            } else {
                String::new()
            };

            ListItem::new(format!("{} {}{}", prefix, name, unread)).style(style)
        })
        .collect();

    let list = List::new(conversations)
        .block(Block::default().title(" Chats ").borders(Borders::ALL));
    frame.render_widget(list, chunks[1]);
}

fn render_main(frame: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // Messages area
    if let Some(conv) = state.active_conversation() {
        let messages: Vec<Line> = conv
            .messages
            .iter()
            .map(|msg| {
                let style = if msg.outgoing {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::Green)
                };
                let prefix = if msg.outgoing { "→" } else { "←" };
                Line::from(vec![
                    Span::styled(format!("{} ", prefix), style),
                    Span::raw(&msg.content),
                ])
            })
            .collect();

        let messages_widget = Paragraph::new(messages)
            .block(
                Block::default()
                    .title(format!(" {} ", conv.contact.username))
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(messages_widget, chunks[0]);
    } else {
        let placeholder = Paragraph::new("Select a conversation or /add <username>")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title(" Messages ").borders(Borders::ALL));
        frame.render_widget(placeholder, chunks[0]);
    }

    // Input area
    let input = Paragraph::new(state.input.as_str())
        .block(Block::default().title(" > ").borders(Borders::ALL));
    frame.render_widget(input, chunks[1]);
}
```

**Step 3: Update main.rs**

`crates/whspr-client/src/main.rs`:
```rust
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
};

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
        if let Some(conv) = state.conversations.get_mut(&conv_name) {
            // TODO: Encrypt with ratchet
            let payload = SendPayload {
                to: conv_name.clone(),
                ciphertext: input.as_bytes().to_vec(), // Plaintext for now
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
            // TODO: Decrypt with ratchet
            let content = String::from_utf8_lossy(&payload.ciphertext).to_string();

            if let Some(conv) = state.conversations.get_mut(&payload.from) {
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
```

**Step 4: Add dirs dependency**

Add to `crates/whspr-client/Cargo.toml`:
```toml
dirs = "5"
```

**Step 5: Build and verify**

Run: `cargo build -p whspr-client`
Expected: Compiles successfully

**Step 6: Commit**

```bash
git add -A
git commit -m "feat(client): add basic TUI with conversation management"
```

---

## Phase 4: Integration & Polish

### Task 13: Integrate E2E Encryption

**Files:**
- Modify: `crates/whspr-client/src/state.rs`
- Modify: `crates/whspr-client/src/main.rs`

This task integrates the Double Ratchet encryption into actual message sending/receiving. Update the message handling in main.rs to:

1. When starting a conversation, perform X3DH key exchange
2. Initialize RatchetSession for the conversation
3. Encrypt outgoing messages with ratchet.encrypt()
4. Decrypt incoming messages with ratchet.decrypt()

**Step 1: Update state.rs to include crypto imports**

Add to top of `crates/whspr-client/src/state.rs`:
```rust
use whspr_protocol::crypto::{RatchetSession, x3dh_initiator, MessageHeader};
use x25519_dalek::StaticSecret;
```

**Step 2: Update main.rs message handling** (key sections)

In `handle_input`, when sending:
```rust
// If no ratchet, initialize one
if conv.ratchet.is_none() {
    let ephemeral = StaticSecret::random_from_rng(rand::thread_rng());
    let shared_secret = x3dh_initiator(
        state.identity.x25519_secret(),
        &ephemeral,
        &conv.contact.keys.identity_key,
        &conv.contact.keys.prekey,
    );
    conv.ratchet = Some(RatchetSession::init_alice(&shared_secret, conv.contact.keys.prekey));
}

let ratchet = conv.ratchet.as_mut().unwrap();
let (header, ciphertext) = ratchet.encrypt(input.as_bytes())?;

// Serialize header + ciphertext
let mut encrypted = encode_payload(&header)?;
encrypted.extend(ciphertext);

let payload = SendPayload {
    to: conv_name.clone(),
    ciphertext: encrypted,
};
```

When receiving in `handle_incoming_frame`:
```rust
// Deserialize header and decrypt
let header: MessageHeader = decode_payload(&payload.ciphertext[../* header size */])?;
let ciphertext = &payload.ciphertext[/* after header */..];

if conv.ratchet.is_none() {
    // Initialize as Bob (responder)
    // This requires storing the prekey secret - add to Identity
}

let ratchet = conv.ratchet.as_mut().unwrap();
let plaintext = ratchet.decrypt(&header, ciphertext)?;
let content = String::from_utf8_lossy(&plaintext).to_string();
```

**Step 3: Build and test manually**

Run: `cargo build`
Expected: Compiles (encryption integration may need debugging)

**Step 4: Commit**

```bash
git add -A
git commit -m "feat: integrate Double Ratchet encryption into message flow"
```

---

### Task 14: Final Polish & Testing

**Files:**
- Various cleanup and testing

**Step 1: Run full build**

Run: `cargo build --release`
Expected: Clean build

**Step 2: Test manually**

1. Start server: `./target/release/whspr-server`
2. Start client 1: `./target/release/whspr`
3. Start client 2: `./target/release/whspr` (in another terminal)
4. Use `/add <username>` to add each other
5. Send messages back and forth

**Step 3: Final commit**

```bash
git add -A
git commit -m "chore: final polish and cleanup"
```

---

## Summary

**Total tasks: 14**

**Phase 1 (Foundation):** Tasks 1-5 — Workspace setup, wire protocol, messages, identity, crypto
**Phase 2 (Server):** Tasks 6-9 — QUIC server, user store, sessions, connection handling
**Phase 3 (Client):** Tasks 10-12 — QUIC client, state management, TUI
**Phase 4 (Integration):** Tasks 13-14 — E2E encryption integration, polish

Each task follows TDD where applicable and produces a working, committed increment.
