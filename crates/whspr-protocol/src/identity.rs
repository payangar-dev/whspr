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
    let sig = Signature::from_bytes(signature);
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
