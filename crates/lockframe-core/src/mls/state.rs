//! MLS group state for storage and validation

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Minimal MLS group state for server-side validation
///
/// The server does not perform MLS cryptographic operations - it only validates
/// frames and sequences them. This struct contains the lightweight metadata
/// needed for that validation:
/// - Epoch matching (reject stale frames)
/// - Membership checking (reject frames from non-members)
/// - Signature verification (authenticate senders)
/// - Tree hash for consistency checks
///
/// The full MLS group state (key schedule, ratchet tree, etc.) lives only on
/// clients. The server is a "dumb relay" that validates and sequences frames
/// without access to encryption keys.
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
    /// `tree_hash`)
    pub tree_hash: [u8; 32],

    /// List of member IDs currently in the group
    ///
    /// Used for validation: only members can send messages
    pub members: Vec<u64>,

    /// Map of member ID to their Ed25519 public key (32 bytes)
    ///
    /// Used for signature verification on incoming frames.
    /// Keys are extracted from MLS credentials when clients export group state.
    #[serde(default)]
    pub member_keys: HashMap<u64, [u8; 32]>,
}

impl MlsGroupState {
    /// Create a new MLS group state
    pub fn new(room_id: u128, epoch: u64, tree_hash: [u8; 32], members: Vec<u64>) -> Self {
        Self { room_id, epoch, tree_hash, members, member_keys: HashMap::new() }
    }

    /// Create a new MLS group state with public keys for signature verification
    pub fn with_keys(
        room_id: u128,
        epoch: u64,
        tree_hash: [u8; 32],
        members: Vec<u64>,
        member_keys: HashMap<u64, [u8; 32]>,
    ) -> Self {
        Self { room_id, epoch, tree_hash, members, member_keys }
    }

    /// Check if a member is in the group
    pub fn is_member(&self, member_id: u64) -> bool {
        self.members.contains(&member_id)
    }

    /// Number of members in the group.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Member's Ed25519 public key for signature verification. `None` if member
    /// not found or no key stored.
    pub fn member_key(&self, member_id: u64) -> Option<VerifyingKey> {
        self.member_keys.get(&member_id).and_then(|bytes| VerifyingKey::from_bytes(bytes).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state = MlsGroupState::new(100, 5, [42u8; 32], vec![1, 2, 3]);

        assert_eq!(state.room_id, 100);
        assert_eq!(state.epoch, 5);
        assert_eq!(state.tree_hash, [42u8; 32]);
        assert_eq!(state.members, vec![1, 2, 3]);
    }

    #[test]
    fn test_is_member() {
        let state = MlsGroupState::new(100, 0, [0u8; 32], vec![100, 200, 300]);

        assert!(state.is_member(100));
        assert!(state.is_member(200));
        assert!(state.is_member(300));
        assert!(!state.is_member(400));
    }

    #[test]
    fn test_member_count() {
        let state = MlsGroupState::new(100, 0, [0u8; 32], vec![1, 2, 3, 4, 5]);

        assert_eq!(state.member_count(), 5);
    }

    #[test]
    fn test_serialize_deserialize() {
        let original =
            MlsGroupState::new(0x12345678_90abcdef_12345678_90abcdef, 42, [0xffu8; 32], vec![
                100, 200, 300, 400,
            ]);

        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&original, &mut encoded).expect("serialization failed");

        let decoded: MlsGroupState =
            ciborium::de::from_reader(&encoded[..]).expect("deserialization failed");

        assert_eq!(decoded, original);
    }

    #[test]
    fn test_clone() {
        let state = MlsGroupState::new(100, 5, [1u8; 32], vec![1, 2]);

        let cloned = state.clone();

        assert_eq!(cloned.room_id, state.room_id);
        assert_eq!(cloned.epoch, state.epoch);
        assert_eq!(cloned.tree_hash, state.tree_hash);
        assert_eq!(cloned.members, state.members);
    }
}
