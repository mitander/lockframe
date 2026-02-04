//! CBOR-encoded protocol messages.
//!
//! Frame headers are raw binary for performance, but payloads use CBOR for type
//! safety and forward compatibility. The `Payload` enum covers all message
//! types: session management (Hello, Ping, etc.), MLS operations (Welcome,
//! Commit), and application messages.
//!
//! We chose CBOR over alternatives because it's self-describing (field names
//! embedded), compact, and doesn't need code generation. The sequencer never
//! deserializes payloads - only clients do.
//!
//! # Invariants
//!
//! Each payload variant maps to exactly one opcode (enforced by match
//! exhaustiveness). Round-trip encoding must produce identical values.

pub mod app;
pub mod mls;
pub mod moderation;
pub mod session;

use bytes::BufMut;
use serde::{Deserialize, Serialize};

use crate::{
    Frame, FrameHeader, Opcode,
    errors::{ProtocolError, Result},
};

/// All possible frame payloads
///
/// The payload type is determined by the `Opcode` in the frame header,
/// so we serialize only the inner struct content (no variant tag in CBOR).
///
/// # Invariants
///
/// - Opcode Uniqueness: Each payload variant corresponds to exactly one
///   `Opcode`. The `opcode()` method returns a unique opcode for each variant.
///
/// - Serialization Consistency: Encoding a `Payload` and then decoding it with
///   the same opcode MUST produce an equivalent value. This is verified by
///   round-trip tests.
///
/// # Security
///
/// - No Variant Tag: Unlike typical Rust enum serialization, we do NOT
///   serialize the variant discriminator. The frame header's `opcode` field
///   already identifies the payload type. This prevents attackers from sending
///   mismatched opcode/payload pairs.
///
/// - Exhaustive Matching: All methods use exhaustive `match` statements. Adding
///   a new variant will cause compile errors in `encode()`, `decode()`, and
///   `opcode()`, ensuring no variant is accidentally left unhandled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    // Session Management
    /// Initial handshake
    Hello(session::Hello),
    /// Server response to Hello
    HelloReply(session::HelloReply),
    /// Graceful disconnect
    Goodbye(session::Goodbye),
    /// Ping for keepalive
    Ping,
    /// Pong response
    Pong,
    /// Client sync request
    SyncRequest(session::SyncRequest),
    /// Server sync response
    SyncResponse(session::SyncResponse),

    // MLS Operations
    /// Key package upload
    KeyPackage(mls::KeyPackageData),
    /// MLS proposal
    Proposal(mls::ProposalData),
    /// MLS commit
    Commit(mls::CommitData),
    /// MLS welcome message
    Welcome(mls::WelcomeData),
    /// Publish `KeyPackage` to server registry
    KeyPackagePublish(mls::KeyPackagePublishRequest),
    /// Fetch `KeyPackage` from server registry
    KeyPackageFetch(mls::KeyPackageFetchPayload),
    /// Request `GroupInfo` for external join
    GroupInfoRequest(mls::GroupInfoRequest),
    /// `GroupInfo` response for external join
    GroupInfo(mls::GroupInfoPayload),

    // Application Messages
    /// Encrypted application message
    AppMessage(app::EncryptedMessage),
    /// Delivery receipt
    AppReceipt(app::Receipt),
    /// Message reaction
    AppReaction(app::Reaction),

    // Moderation
    /// Redact message content
    Redact(moderation::Redact),
    /// Ban user
    Ban(moderation::Ban),
    /// Kick user
    Kick(moderation::Kick),

    // Error frame
    /// Error response
    Error(ErrorPayload),
}

/// Error payload for error frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Error code identifying the type of error.
    pub code: u16,
    /// Human-readable error message.
    pub message: String,
    /// Optional retry-after duration in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

impl ErrorPayload {
    /// Frame was rejected by the server.
    pub const FRAME_REJECTED: u16 = 0x0001;
    /// Room does not exist.
    pub const ROOM_NOT_FOUND: u16 = 0x0002;
    /// Storage operation failed.
    pub const STORAGE_ERROR: u16 = 0x0003;
    /// Invalid payload format.
    pub const INVALID_PAYLOAD: u16 = 0x0004;
    /// MLS validation or operation failed.
    pub const MLS_ERROR: u16 = 0x0005;
    /// Sequencer error (e.g., duplicate log index).
    pub const SEQUENCER_ERROR: u16 = 0x0006;
    /// `KeyPackage` not found in registry.
    pub const KEYPACKAGE_NOT_FOUND: u16 = 0x0007;

    /// Create a frame rejection error.
    pub fn frame_rejected(reason: impl Into<String>) -> Self {
        Self { code: Self::FRAME_REJECTED, message: reason.into(), retry_after: None }
    }

    /// Create a room not found error.
    pub fn room_not_found(room_id: u128) -> Self {
        Self {
            code: Self::ROOM_NOT_FOUND,
            message: format!("room not found: {room_id:032x}"),
            retry_after: None,
        }
    }

    /// Create a storage error.
    pub fn storage_error(msg: impl Into<String>) -> Self {
        Self { code: Self::STORAGE_ERROR, message: msg.into(), retry_after: None }
    }

    /// Create an invalid payload error.
    pub fn invalid_payload(msg: impl Into<String>) -> Self {
        Self { code: Self::INVALID_PAYLOAD, message: msg.into(), retry_after: None }
    }

    /// Create an MLS error.
    pub fn mls_error(msg: impl Into<String>) -> Self {
        Self { code: Self::MLS_ERROR, message: msg.into(), retry_after: None }
    }

    /// Create a sequencer error.
    pub fn sequencer_error(msg: impl Into<String>) -> Self {
        Self { code: Self::SEQUENCER_ERROR, message: msg.into(), retry_after: None }
    }

    /// Create a `KeyPackage` not found error.
    pub fn keypackage_not_found(user_id: u64) -> Self {
        Self {
            code: Self::KEYPACKAGE_NOT_FOUND,
            message: format!("no KeyPackage for user {user_id}"),
            retry_after: None,
        }
    }
}

impl Payload {
    /// Opcode corresponding to this payload type.
    #[must_use]
    pub const fn opcode(&self) -> Opcode {
        match self {
            Self::Hello(_) => Opcode::Hello,
            Self::HelloReply(_) => Opcode::HelloReply,
            Self::Goodbye(_) => Opcode::Goodbye,
            Self::Ping => Opcode::Ping,
            Self::Pong => Opcode::Pong,
            Self::SyncRequest(_) => Opcode::SyncRequest,
            Self::SyncResponse(_) => Opcode::SyncResponse,
            Self::KeyPackage(_) => Opcode::KeyPackage,
            Self::Proposal(_) => Opcode::Proposal,
            Self::Commit(_) => Opcode::Commit,
            Self::Welcome(_) => Opcode::Welcome,
            Self::KeyPackagePublish(_) => Opcode::KeyPackagePublish,
            Self::KeyPackageFetch(_) => Opcode::KeyPackageFetch,
            Self::GroupInfoRequest(_) => Opcode::GroupInfoRequest,
            Self::GroupInfo(_) => Opcode::GroupInfo,
            Self::AppMessage(_) => Opcode::AppMessage,
            Self::AppReceipt(_) => Opcode::AppReceipt,
            Self::AppReaction(_) => Opcode::AppReaction,
            Self::Redact(_) => Opcode::Redact,
            Self::Ban(_) => Opcode::Ban,
            Self::Kick(_) => Opcode::Kick,
            Self::Error(_) => Opcode::Error,
        }
    }

    /// Encode payload to buffer (zero-allocation)
    ///
    /// Serializes only the inner struct, NOT the variant tag.
    /// The frame header's opcode already identifies the payload type.
    ///
    /// # Security
    ///
    /// - No Size Limit Enforcement: This function does NOT check if the encoded
    ///   size exceeds [`FrameHeader::MAX_PAYLOAD_SIZE`]. Size validation
    ///   happens later in [`Frame::encode`]. This separation allows encoding
    ///   for testing or inspection without artificial limits.
    ///
    /// - Deterministic Encoding: CBOR uses deterministic (canonical) encoding.
    ///   The same payload always produces the same byte sequence, which is
    ///   critical for signature verification.
    ///
    /// # Errors
    ///
    /// - `ProtocolError::CborEncode` if serialization fails
    pub fn encode(&self, dst: &mut impl BufMut) -> Result<()> {
        let mut writer = dst.writer();

        match self {
            Self::Hello(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::HelloReply(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Goodbye(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Ping | Self::Pong => Ok(()), // Zero-byte payloads
            Self::SyncRequest(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::SyncResponse(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::KeyPackage(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Proposal(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Commit(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Welcome(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::KeyPackagePublish(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::KeyPackageFetch(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::GroupInfoRequest(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::GroupInfo(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::AppMessage(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::AppReceipt(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::AppReaction(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Redact(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Ban(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Kick(inner) => ciborium::ser::into_writer(inner, &mut writer),
            Self::Error(inner) => ciborium::ser::into_writer(inner, &mut writer),
        }
        .map_err(|e| ProtocolError::CborEncode(e.to_string()))
    }

    /// Decode payload from bytes based on opcode
    ///
    ///
    /// # Security
    ///
    /// - Size Validation First: The size check happens BEFORE CBOR parsing
    ///   begins. This prevents the CBOR parser from processing maliciously
    ///   large inputs that could exhaust memory or CPU.
    ///
    /// - Fail on Unknown Opcodes: Unknown opcodes are rejected with an error
    ///   rather than being silently ignored. This prevents version confusion
    ///   attacks where an old client misinterprets frames from a newer protocol
    ///   version.
    ///
    /// # Errors
    ///
    /// - `ProtocolError::PayloadTooLarge` if bytes exceed `MAX_PAYLOAD_SIZE`
    ///   (16 MB)
    /// - `ProtocolError::CborDecode` if CBOR deserialization fails
    /// - `ProtocolError::CborDecode` if opcode is not recognized
    pub fn decode(opcode: Opcode, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > FrameHeader::MAX_PAYLOAD_SIZE as usize {
            return Err(ProtocolError::PayloadTooLarge {
                size: bytes.len(),
                max: FrameHeader::MAX_PAYLOAD_SIZE as usize,
            });
        }

        let payload = match opcode {
            Opcode::Hello => Self::Hello(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::HelloReply => Self::HelloReply(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Goodbye => Self::Goodbye(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Ping => Self::Ping,
            Opcode::Pong => Self::Pong,
            Opcode::SyncRequest => Self::SyncRequest(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::SyncResponse => Self::SyncResponse(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::KeyPackage => Self::KeyPackage(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Proposal => Self::Proposal(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Commit => Self::Commit(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Welcome => Self::Welcome(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::KeyPackagePublish => Self::KeyPackagePublish(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::KeyPackageFetch => Self::KeyPackageFetch(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::GroupInfoRequest => Self::GroupInfoRequest(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::GroupInfo => Self::GroupInfo(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::AppMessage => Self::AppMessage(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::AppReceipt => Self::AppReceipt(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::AppReaction => Self::AppReaction(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Redact => Self::Redact(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Ban => Self::Ban(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Kick => Self::Kick(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            Opcode::Error => Self::Error(
                ciborium::de::from_reader(bytes)
                    .map_err(|e| ProtocolError::CborDecode(e.to_string()))?,
            ),
            _ => {
                return Err(ProtocolError::CborDecode(format!(
                    "Unsupported opcode: {:#06x}",
                    opcode.to_u16()
                )));
            },
        };

        Ok(payload)
    }

    /// Convert payload into a transport frame
    ///
    /// This method handles the logic-to-transport conversion:
    /// - Encodes the payload to CBOR bytes
    /// - Sets the correct opcode in the header
    /// - Creates a Frame with automatic `payload_size` calculation
    ///
    /// # Errors
    ///
    /// - `ProtocolError::CborEncode` if serialization fails
    pub fn into_frame(self, mut header: FrameHeader) -> Result<Frame> {
        let mut buf = Vec::new();
        self.encode(&mut buf)?;
        header.opcode = self.opcode().to_u16().to_be_bytes();
        Ok(Frame::new(header, buf))
    }

    /// Parse payload from a raw transport frame
    ///
    /// This method handles the transport-to-logic conversion:
    /// - Extracts the opcode from the frame header
    /// - Decodes the payload bytes based on the opcode
    ///
    /// # Errors
    ///
    /// - `ProtocolError::CborDecode` if opcode is invalid or unsupported
    /// - `ProtocolError::CborDecode` if CBOR deserialization fails
    /// - `ProtocolError::PayloadTooLarge` if payload exceeds maximum size
    pub fn from_frame(frame: &Frame) -> Result<Self> {
        let opcode = frame.header.opcode_enum().ok_or_else(|| {
            ProtocolError::CborDecode(format!("Invalid opcode: {:#06x}", frame.header.opcode()))
        })?;
        Self::decode(opcode, &frame.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_ping_round_trip() {
        let payload = Payload::Ping;

        // Create valid header
        let mut bytes = [0u8; 128];
        bytes[0..4].copy_from_slice(&FrameHeader::MAGIC.to_be_bytes());
        bytes[4] = FrameHeader::VERSION;
        let header = *FrameHeader::from_bytes(&bytes).unwrap();

        // Convert to frame and back
        let frame = payload.clone().into_frame(header).expect("should create frame");
        let decoded = Payload::from_frame(&frame).expect("should parse payload");
        assert_eq!(payload, decoded);
    }

    #[test]
    fn payload_error_round_trip() {
        let payload = Payload::Error(ErrorPayload {
            code: 0x00FF,
            message: "Test error".to_string(),
            retry_after: Some(30),
        });

        // Create valid header
        let mut bytes = [0u8; 128];
        bytes[0..4].copy_from_slice(&FrameHeader::MAGIC.to_be_bytes());
        bytes[4] = FrameHeader::VERSION;
        let header = *FrameHeader::from_bytes(&bytes).unwrap();

        // Convert to frame and back
        let frame = payload.clone().into_frame(header).expect("should create frame");
        let decoded = Payload::from_frame(&frame).expect("should parse payload");
        assert_eq!(payload, decoded);
    }
}
