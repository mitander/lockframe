//! MLS group state for storage and validation

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Minimal MLS group state for validation and persistence
///
/// This struct separates lightweight validation state from the heavy OpenMLS
/// group object. The sequencer and validator only need epoch/members/tree_hash,
/// not the full MLS group with all its cryptographic state.
///
/// # Storage Strategy
///
/// - Lightweight fields (epoch, tree_hash, members) are directly accessible
/// - Full OpenMLS group state is stored as an opaque serialized blob
/// - This allows fast validation without deserializing the entire group
///
/// # Serialization
///
/// This type derives Serialize/Deserialize for storage persistence.
/// The format is CBOR (via ciborium) for compatibility with the wire protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MlsGroupState {
    /// Room ID this group belongs to
    pub room_id: u128,

    /// Current MLS epoch number
    ///
    /// Used for validation: frames must match current epoch
    pub epoch: u64,

    /// Tree hash of the current ratchet tree
    ///
    /// Used for consistency checks (all clients should converge to same
    /// tree_hash)
    pub tree_hash: [u8; 32],

    /// List of member IDs currently in the group
    ///
    /// Used for validation: only members can send messages
    pub members: Vec<u64>,

    /// Map of member ID to their Ed25519 public key (32 bytes)
    ///
    /// Used for signature verification on incoming frames.
    /// Keys are extracted from MLS credentials when exporting group state.
    #[serde(default)]
    pub member_keys: HashMap<u64, [u8; 32]>,

    /// Serialized OpenMLS group state (opaque blob)
    ///
    /// This is the full MlsGroup from openmls, serialized.
    /// The sequencer doesn't need to deserialize this for validation.
    /// Only the full MLS client needs to deserialize this to process
    /// proposals/commits.
    pub openmls_state: Vec<u8>,
}

impl MlsGroupState {
    /// Create a new MLS group state
    pub fn new(
        room_id: u128,
        epoch: u64,
        tree_hash: [u8; 32],
        members: Vec<u64>,
        openmls_state: Vec<u8>,
    ) -> Self {
        Self { room_id, epoch, tree_hash, members, member_keys: HashMap::new(), openmls_state }
    }

    /// Create a new MLS group state with public keys for signature verification
    pub fn with_keys(
        room_id: u128,
        epoch: u64,
        tree_hash: [u8; 32],
        members: Vec<u64>,
        member_keys: HashMap<u64, [u8; 32]>,
        openmls_state: Vec<u8>,
    ) -> Self {
        Self { room_id, epoch, tree_hash, members, member_keys, openmls_state }
    }

    /// Check if a member is in the group
    pub fn is_member(&self, member_id: u64) -> bool {
        self.members.contains(&member_id)
    }

    /// Get the number of members in the group
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Get a member's public key for signature verification
    ///
    /// Returns `None` if the member doesn't exist or has no stored key.
    pub fn member_key(&self, member_id: u64) -> Option<VerifyingKey> {
        self.member_keys.get(&member_id).and_then(|bytes| VerifyingKey::from_bytes(bytes).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state =
            MlsGroupState::new(100, 5, [42u8; 32], vec![1, 2, 3], vec![0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(state.room_id, 100);
        assert_eq!(state.epoch, 5);
        assert_eq!(state.tree_hash, [42u8; 32]);
        assert_eq!(state.members, vec![1, 2, 3]);
        assert_eq!(state.openmls_state, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_is_member() {
        let state = MlsGroupState::new(100, 0, [0u8; 32], vec![100, 200, 300], vec![]);

        assert!(state.is_member(100));
        assert!(state.is_member(200));
        assert!(state.is_member(300));
        assert!(!state.is_member(400));
    }

    #[test]
    fn test_member_count() {
        let state = MlsGroupState::new(100, 0, [0u8; 32], vec![1, 2, 3, 4, 5], vec![]);

        assert_eq!(state.member_count(), 5);
    }

    #[test]
    fn test_serialize_deserialize() {
        let original = MlsGroupState::new(
            0x12345678_90abcdef_12345678_90abcdef,
            42,
            [0xffu8; 32],
            vec![100, 200, 300, 400],
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        );

        // Serialize to CBOR
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&original, &mut encoded).expect("serialization failed");

        // Deserialize back
        let decoded: MlsGroupState =
            ciborium::de::from_reader(&encoded[..]).expect("deserialization failed");

        assert_eq!(decoded, original);
    }

    #[test]
    fn test_clone() {
        let state = MlsGroupState::new(100, 5, [1u8; 32], vec![1, 2], vec![0xff]);

        let cloned = state.clone();

        assert_eq!(cloned.room_id, state.room_id);
        assert_eq!(cloned.epoch, state.epoch);
        assert_eq!(cloned.tree_hash, state.tree_hash);
        assert_eq!(cloned.members, state.members);
        assert_eq!(cloned.openmls_state, state.openmls_state);
    }
}
