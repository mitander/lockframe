//! Operation codes for Lockframe protocol frames.
//!
//! Opcodes identify the operation type and are organized into ranges by
//! functionality. This lets routers make efficient decisions by checking just
//! the high byte - federation frames (0x4xxx) can route to a specialized
//! handler without fully parsing the opcode.
//!
//! # Opcode Ranges
//!
//! - `0x0000-0x00FF`: Session Management (connection lifecycle)
//! - `0x1000-0x1FFF`: MLS Operations (group key management)
//! - `0x2000-0x2FFF`: Application Messages (user content)
//! - `0x3000-0x3FFF`: Moderation (content/user management)
//! - `0x4000-0x4FFF`: Federation (inter-server communication)
//! - `0x5000-0x5FFF`: Storage (content-addressed storage)

use serde_repr::{Deserialize_repr, Serialize_repr};

/// Frame operation codes
///
/// Each opcode represents a distinct protocol operation and determines how the
/// frame payload should be interpreted and routed. Serialized as Big Endian u16
/// values in the frame header.
///
/// # Security
///
/// Unknown opcodes return None rather than panicking - frames with unknown
/// opcodes should be rejected. Each opcode must be explicitly handled with no
/// "default" behavior, preventing accidental mishandling of malicious or
/// corrupted frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u16)]
pub enum Opcode {
    // Session Management (0x0000-0x00FF)
    /// Initial handshake
    Hello = 0x0001,
    /// Server response to Hello
    HelloReply = 0x0002,
    /// Graceful disconnect
    Goodbye = 0x0003,
    /// Keepalive ping
    Ping = 0x0004,
    /// Keepalive response
    Pong = 0x0005,
    /// Request sync for a room (client → server)
    SyncRequest = 0x0006,
    /// Sync response with frames (server → client)
    SyncResponse = 0x0007,
    /// Error frame
    Error = 0x00FF,

    // MLS Operations (0x1000-0x1FFF)
    /// Upload key package
    KeyPackage = 0x1000,
    /// MLS proposal
    Proposal = 0x1001,
    /// MLS commit
    Commit = 0x1002,
    /// MLS welcome message
    Welcome = 0x1003,
    /// Group context information
    GroupInfo = 0x1004,
    /// Pre-shared key proposal
    PSKProposal = 0x1005,
    /// Reinitialize group
    ReInit = 0x1006,
    /// Server-generated external commit
    ExternalCommit = 0x1007,
    /// Publish KeyPackage to registry (client → server)
    KeyPackagePublish = 0x1008,
    /// Fetch KeyPackage from registry (client → server, server → client)
    KeyPackageFetch = 0x1009,

    // Application Messages (0x2000-0x2FFF)
    /// Encrypted application message
    AppMessage = 0x2000,
    /// Delivery receipt
    AppReceipt = 0x2001,
    /// Message reaction (emoji, etc.)
    AppReaction = 0x2002,
    /// Message edit
    AppEdit = 0x2003,
    /// Message deletion
    AppDelete = 0x2004,
    /// Typing indicator
    Typing = 0x2005,
    /// Presence/online status
    Presence = 0x2006,

    // Moderation (0x3000-0x3FFF)
    /// Remove message content
    Redact = 0x3000,
    /// Ban user from room
    Ban = 0x3001,
    /// Unban user
    Unban = 0x3002,
    /// Remove user from room
    Kick = 0x3003,
    /// Mute user
    Mute = 0x3004,
    /// Pin message
    Pin = 0x3005,
    /// Report content
    Report = 0x3006,

    // Federation (0x4000-0x4FFF)
    /// Federated log append
    FedAppend = 0x4000,
    /// Sync request
    FedSync = 0x4001,
    /// Federation acknowledgment
    FedAck = 0x4002,
    /// Federation rejection
    FedNack = 0x4003,
    /// Query remote hub
    FedQuery = 0x4004,

    // Storage (0x5000-0x5FFF)
    /// Store content-addressed blob
    CASPut = 0x5000,
    /// Retrieve blob by hash
    CASGet = 0x5001,
    /// Delete blob
    CASDelete = 0x5002,
    /// Storage proof/attestation
    CASProof = 0x5003,
}

impl Opcode {
    /// Convert to raw u16 value
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }

    /// Convert from raw u16 value
    ///
    /// Returns `None` if the value doesn't correspond to a known opcode.
    ///
    /// # Security
    ///
    /// This function is total (defined for all u16 values) and
    /// infallible. It returns `Option<Self>` to distinguish between
    /// known and unknown opcodes, allowing callers to reject frames with
    /// invalid opcodes explicitly.
    ///
    /// Unknown opcodes MUST be treated as protocol errors, not silently
    /// ignored.
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Hello),
            0x0002 => Some(Self::HelloReply),
            0x0003 => Some(Self::Goodbye),
            0x0004 => Some(Self::Ping),
            0x0005 => Some(Self::Pong),
            0x0006 => Some(Self::SyncRequest),
            0x0007 => Some(Self::SyncResponse),
            0x00FF => Some(Self::Error),

            0x1000 => Some(Self::KeyPackage),
            0x1001 => Some(Self::Proposal),
            0x1002 => Some(Self::Commit),
            0x1003 => Some(Self::Welcome),
            0x1004 => Some(Self::GroupInfo),
            0x1005 => Some(Self::PSKProposal),
            0x1006 => Some(Self::ReInit),
            0x1007 => Some(Self::ExternalCommit),
            0x1008 => Some(Self::KeyPackagePublish),
            0x1009 => Some(Self::KeyPackageFetch),

            0x2000 => Some(Self::AppMessage),
            0x2001 => Some(Self::AppReceipt),
            0x2002 => Some(Self::AppReaction),
            0x2003 => Some(Self::AppEdit),
            0x2004 => Some(Self::AppDelete),
            0x2005 => Some(Self::Typing),
            0x2006 => Some(Self::Presence),

            0x3000 => Some(Self::Redact),
            0x3001 => Some(Self::Ban),
            0x3002 => Some(Self::Unban),
            0x3003 => Some(Self::Kick),
            0x3004 => Some(Self::Mute),
            0x3005 => Some(Self::Pin),
            0x3006 => Some(Self::Report),

            0x4000 => Some(Self::FedAppend),
            0x4001 => Some(Self::FedSync),
            0x4002 => Some(Self::FedAck),
            0x4003 => Some(Self::FedNack),
            0x4004 => Some(Self::FedQuery),

            0x5000 => Some(Self::CASPut),
            0x5001 => Some(Self::CASGet),
            0x5002 => Some(Self::CASDelete),
            0x5003 => Some(Self::CASProof),

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_round_trip() {
        let opcodes = [
            Opcode::Hello,
            Opcode::Commit,
            Opcode::AppMessage,
            Opcode::Redact,
            Opcode::FedAppend,
            Opcode::CASPut,
        ];

        for opcode in opcodes {
            let value = opcode.to_u16();
            let parsed = Opcode::from_u16(value);
            assert_eq!(Some(opcode), parsed);
        }
    }

    #[test]
    fn invalid_opcode() {
        assert_eq!(Opcode::from_u16(0x9999), None);
        assert_eq!(Opcode::from_u16(0x0000), None);
    }
}
