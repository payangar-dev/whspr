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
