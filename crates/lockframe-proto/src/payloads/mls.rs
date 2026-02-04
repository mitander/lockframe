//! MLS operation payload types.
//!
//! These types wrap raw MLS protocol data. The actual MLS cryptographic
//! operations are handled by the `openmls` library in higher layers.

use serde::{Deserialize, Serialize};

/// Key package upload
///
/// Contains a serialized MLS `KeyPackage` for joining groups.
///
/// # Protocol Flow
///
/// Sent by a client who wants to join a room. The server stores this
/// `KeyPackage` and later includes it in a Welcome message when the client is
/// added to the group by another member's Commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageData {
    /// Serialized MLS `KeyPackage` (from openmls)
    pub key_package_bytes: Vec<u8>,
}

/// MLS proposal
///
/// Proposals are staged changes to the group (add member, remove member, etc.)
///
/// # Protocol Flow
///
/// Proposals are sent to suggest changes but don't take effect immediately.
/// They must be "committed" by a Commit message. Flow:
/// 1. Member sends Proposal (e.g., Add, Remove, Update)
/// 2. Server validates and broadcasts to group
/// 3. Any member can send Commit referencing pending Proposals
/// 4. Commit advances the group epoch and applies all pending Proposals
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalData {
    /// Serialized MLS Proposal
    pub proposal_bytes: Vec<u8>,

    /// Proposal type hint (for routing/logging)
    pub proposal_type: ProposalType,
}

/// Type of MLS proposal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalType {
    /// Add a new member
    Add,
    /// Remove an existing member
    Remove,
    /// Update own key material
    Update,
    /// Pre-shared key
    PSK,
    /// Reinitialize the group with different parameters
    ReInit,
    /// External initialization proposal
    ExternalInit,
    /// Modify group context extensions
    GroupContextExtensions,
}

/// MLS commit
///
/// Commits apply one or more proposals and advance the epoch.
///
/// # Protocol Flow
///
/// Sent by a group member to finalize pending Proposals and advance the epoch:
/// 1. Member creates Commit referencing pending Proposals
/// 2. Server validates Commit (signatures, epoch match)
/// 3. Server sequences Commit with monotonic `log_index`
/// 4. Server broadcasts to all group members
/// 5. All members apply Commit and advance to new epoch
/// 6. Old epoch keys are deleted (forward secrecy)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitData {
    /// Serialized MLS Commit
    pub commit_bytes: Vec<u8>,

    /// New epoch number
    pub new_epoch: u64,

    /// Tree hash after commit
    pub tree_hash: [u8; 32],

    /// True if this is an external commit (from server or new joiner)
    pub is_external: bool,
}

/// MLS welcome message
///
/// Sent to new members joining the group.
///
/// # Protocol Flow
///
/// Sent to a newly added member after a Commit that included an Add proposal:
/// 1. Member A sends Add proposal (references member B's `KeyPackage`)
/// 2. Member A or another member sends Commit including the Add
/// 3. Server generates Welcome message encrypted to B's `KeyPackage`
/// 4. Server sends Welcome directly to B (not broadcast to group)
/// 5. B decrypts Welcome and joins the group at current epoch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeData {
    /// Serialized MLS Welcome
    pub welcome_bytes: Vec<u8>,

    /// Epoch the new member will join at
    pub epoch: u64,
}

/// Publish a `KeyPackage` to the server registry.
///
/// Sent by a client to make their `KeyPackage` available for others to fetch
/// when adding them to rooms.
///
/// # Protocol Flow
///
/// 1. Client generates `KeyPackage` via `generate_key_package()`
/// 2. Client sends `KeyPackagePublish` with serialized `KeyPackage`
/// 3. Server stores `KeyPackage` indexed by sender's `user_id`
/// 4. Other clients can fetch this `KeyPackage` to add this user to rooms
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackagePublishRequest {
    /// Serialized MLS `KeyPackage` (from openmls/mls-rs).
    pub key_package_bytes: Vec<u8>,
    /// `KeyPackage` hash reference for deduplication.
    pub hash_ref: Vec<u8>,
}

/// Fetch a `KeyPackage` from the server registry.
///
/// Request: Client sends with `user_id` populated, `key_package_bytes` empty.
/// Response: Server sends with `key_package_bytes` populated.
///
/// # Protocol Flow
///
/// 1. Client A wants to add user B to a room
/// 2. Client A sends `KeyPackageFetch` with `user_id = B`
/// 3. Server looks up B's `KeyPackage` and returns it
/// 4. Client A uses the `KeyPackage` in `AddMembers`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageFetchPayload {
    /// User ID whose `KeyPackage` to fetch (request) or owner (response).
    pub user_id: u64,
    /// Serialized MLS `KeyPackage`. Empty in request, populated in response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_package_bytes: Vec<u8>,
    /// `KeyPackage` hash reference. Empty in request, populated in response.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash_ref: Vec<u8>,
}

/// Request `GroupInfo` for external join.
///
/// Sent by a client who wants to join a room via external commit.
///
/// # Protocol Flow
///
/// 1. Client wants to join room without being invited
/// 2. Client sends `GroupInfoRequest` with target `room_id`
/// 3. Server looks up the latest `GroupInfo` for that room
/// 4. Server responds with `GroupInfoPayload` containing the `GroupInfo`
/// 5. Client uses `GroupInfo` to create an external commit
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupInfoRequest {
    /// Room ID to fetch `GroupInfo` for.
    pub room_id: u128,
}

/// `GroupInfo` for external joins (MLS RFC 9420 §12.4.3.1).
///
/// Contains the public group state needed to create an external commit.
///
/// # Protocol Flow
///
/// Sent by the server in response to `GroupInfoRequest`:
/// 1. Server receives `GroupInfoRequest` for a room
/// 2. Server fetches the latest `GroupInfo` from storage
/// 3. Server sends `GroupInfoPayload` to the requesting client
/// 4. Client creates an external commit using the `GroupInfo`
/// 5. Client sends external commit to join the room
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupInfoPayload {
    /// Room this `GroupInfo` belongs to.
    pub room_id: u128,
    /// Current MLS epoch when this `GroupInfo` was generated.
    pub epoch: u64,
    /// TLS-serialized MLS `GroupInfo` (from openmls).
    pub group_info_bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_data_serde() {
        let commit = CommitData {
            commit_bytes: vec![1, 2, 3],
            new_epoch: 42,
            tree_hash: [0; 32],
            is_external: false,
        };

        let cbor = ciborium::ser::into_writer(&commit, Vec::new());
        assert!(cbor.is_ok());
    }

    #[test]
    fn key_package_publish_serde() {
        let publish = KeyPackagePublishRequest {
            key_package_bytes: vec![1, 2, 3, 4],
            hash_ref: vec![5, 6, 7, 8],
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&publish, &mut buf).unwrap();

        let decoded: KeyPackagePublishRequest = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(publish, decoded);
    }

    #[test]
    fn key_package_fetch_serde() {
        // Request (empty key_package_bytes)
        let request = KeyPackageFetchPayload {
            user_id: 42,
            key_package_bytes: Vec::new(),
            hash_ref: Vec::new(),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&request, &mut buf).unwrap();

        let decoded: KeyPackageFetchPayload = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(request, decoded);

        // Response (populated key_package_bytes)
        let response = KeyPackageFetchPayload {
            user_id: 42,
            key_package_bytes: vec![1, 2, 3, 4],
            hash_ref: vec![5, 6, 7, 8],
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&response, &mut buf).unwrap();

        let decoded: KeyPackageFetchPayload = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn group_info_request_serde() {
        let request = GroupInfoRequest { room_id: 42 };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&request, &mut buf).unwrap();

        let decoded: GroupInfoRequest = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(request, decoded);
    }

    #[test]
    fn group_info_payload_serde() {
        let payload =
            GroupInfoPayload { room_id: 42, epoch: 5, group_info_bytes: vec![1, 2, 3, 4, 5] };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf).unwrap();

        let decoded: GroupInfoPayload = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(payload, decoded);
    }
}
