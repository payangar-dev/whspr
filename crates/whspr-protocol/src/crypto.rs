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
