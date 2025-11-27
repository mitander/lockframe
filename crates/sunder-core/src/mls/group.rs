//! Client-side MLS group state machine.

use std::time::Instant;

use sunder_proto::Frame;

use super::error::MlsError;

/// Room identifier (128-bit UUID).
pub type RoomId = u128;

/// Member identifier within a group.
pub type MemberId = u64;

/// Actions that MLS group operations can produce.
///
/// The application layer is responsible for executing these actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsAction {
    /// Send proposal frame to sequencer
    SendProposal(Frame),

    /// Send commit frame to sequencer
    SendCommit(Frame),

    /// Send welcome message to new member
    SendWelcome {
        /// Member ID to send welcome message to
        recipient: MemberId,
        /// Welcome frame containing group secrets
        frame: Frame,
    },

    /// Send application message to group (via sequencer)
    SendMessage(Frame),

    /// Deliver decrypted application message to application
    DeliverMessage {
        /// Member ID who sent the message
        sender: MemberId,
        /// Decrypted message plaintext
        plaintext: Vec<u8>,
    },

    /// Remove this group (we were kicked/banned or left)
    RemoveGroup {
        /// Reason for removal
        reason: String,
    },

    /// Log event for debugging/monitoring
    Log {
        /// Log message
        message: String,
    },
}

/// Client-side MLS group state.
///
/// Represents participation in a single MLS group (room). Clients can be
/// members of multiple groups simultaneously.
///
/// # Invariants
///
/// - Epoch only increases (never decreases)
/// - All members at same epoch have identical tree hash
/// - Only members can encrypt/decrypt messages for current epoch
#[derive(Debug)]
pub struct MlsGroup {
    /// Room identifier
    room_id: RoomId,

    /// Current epoch number (starts at 0)
    current_epoch: u64,

    /// Our member ID in this group
    member_id: MemberId,

    /// Underlying mls-rs group
    /// TODO: Add when we implement create_group
    // mls_group: mls_rs::Group,

    /// Pending commit that we sent (waiting for sequencer acceptance)
    pending_commit: Option<PendingCommit>,
}

/// Tracks a commit we sent that's waiting for sequencer acceptance.
#[derive(Debug, Clone)]
struct PendingCommit {
    /// Epoch this commit will create
    #[allow(dead_code)] // Will be used when we implement commit handling
    target_epoch: u64,

    /// When we sent it (for timeout detection)
    sent_at: Instant,
}

impl MlsGroup {
    /// Create a new MLS group.
    ///
    /// This initializes a new group at epoch 0. The creator becomes the first
    /// member and can add other members via proposals + commits.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Unique identifier for this room
    /// * `member_id` - Our member ID in this group
    /// * `now` - Current time
    ///
    /// # Returns
    ///
    /// A new `MlsGroup` instance and any actions to execute.
    pub fn new(
        room_id: RoomId,
        member_id: MemberId,
        _now: Instant,
    ) -> Result<(Self, Vec<MlsAction>), MlsError> {
        // TODO: Initialize mls-rs group with crypto provider

        let group = Self { room_id, current_epoch: 0, member_id, pending_commit: None };

        let actions = vec![MlsAction::Log {
            message: format!("Created group {} at epoch 0 (member_id={})", room_id, member_id),
        }];

        Ok((group, actions))
    }

    /// Get the current epoch number.
    pub fn epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Get our member ID.
    pub fn member_id(&self) -> MemberId {
        self.member_id
    }

    /// Get the room ID.
    pub fn room_id(&self) -> RoomId {
        self.room_id
    }

    /// Check if we have a pending commit waiting for acceptance.
    pub fn has_pending_commit(&self) -> bool {
        self.pending_commit.is_some()
    }

    /// Check if a pending commit has timed out.
    ///
    /// Returns true if we have a pending commit that's been waiting longer
    /// than the timeout duration.
    pub fn is_commit_timeout(&self, now: Instant, timeout: std::time::Duration) -> bool {
        self.pending_commit
            .as_ref()
            .map_or(false, |pending| now.duration_since(pending.sent_at) > timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_group() {
        let now = Instant::now();
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;
        let member_id = 1;

        let (group, actions) =
            MlsGroup::new(room_id, member_id, now).expect("create should succeed");

        assert_eq!(group.room_id(), room_id);
        assert_eq!(group.member_id(), member_id);
        assert_eq!(group.epoch(), 0);
        assert!(!group.has_pending_commit());

        // Should have logged group creation
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], MlsAction::Log { .. }));
    }

    #[test]
    fn commit_timeout_detection() {
        let now = Instant::now();
        let room_id = 1;
        let member_id = 1;

        let (mut group, _) = MlsGroup::new(room_id, member_id, now).unwrap();

        // No pending commit initially
        assert!(!group.is_commit_timeout(now, std::time::Duration::from_secs(30)));

        // Simulate sending a commit
        group.pending_commit = Some(PendingCommit { target_epoch: 1, sent_at: now });

        // Not timed out immediately
        assert!(!group.is_commit_timeout(now, std::time::Duration::from_secs(30)));

        // Timed out after 31 seconds
        let future = now + std::time::Duration::from_secs(31);
        assert!(group.is_commit_timeout(future, std::time::Duration::from_secs(30)));
    }
}
