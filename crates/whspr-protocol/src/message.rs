use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Public key bundle for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyBundle {
    /// Ed25519 identity public key (32 bytes)
    pub identity_key: [u8; 32],
    /// X25519 prekey for key exchange (32 bytes)
    pub prekey: [u8; 32],
    /// Signature of prekey by identity key (64 bytes)
    #[serde(with = "BigArray")]
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
    #[serde(with = "BigArray")]
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
