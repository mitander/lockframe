//! Room Manager
//!
//! Orchestrates MLS validation and frame sequencing for rooms.
//!
//! ## Architecture
//!
//! ```text
//! Server
//!   ├─ Connections (session layer)
//!   ├─ RoomManager (group layer) ← THIS MODULE
//!   │   ├─ MlsGroups (per-room MLS state)
//!   │   └─ Sequencer (total ordering)
//!   └─ Storage (persistence)
//! ```
//!
//! ## Responsibilities
//!
//! 1. **Room Lifecycle**: Create rooms with authorization metadata
//! 2. **MLS Validation**: Verify frames against group state before sequencing
//! 3. **Frame Sequencing**: Assign log indices for total ordering
//! 4. **Action Generation**: Return actions for driver to execute (Sans-IO)
//!
//! ## Design Decisions
//!
//! - **Explicit room creation**: Prevents accidental rooms, enables future auth
//! - **RoomMetadata**: Extension point for permissions/roles (added later)
//! - **Sans-IO**: All methods return actions, no direct I/O
//! - **Generic over Instant**: Works with any time abstraction

use std::collections::HashMap;

use kalandra_proto::Frame;

use crate::{
    env::Environment,
    mls::{error::MlsError, group::MlsGroup, state::MlsGroupState},
    sequencer::{Sequencer, SequencerAction, SequencerError},
    storage::{Storage, StorageError},
};

/// Metadata about a room (extension point for future authorization)
#[derive(Debug, Clone)]
pub struct RoomMetadata<I> {
    /// User who created the room
    pub creator: u64, // UserId
    /// When the room was created
    pub created_at: I,
    // Future: admins, members, permissions
}

/// Orchestrates MLS validation + frame sequencing per room
pub struct RoomManager<E>
where
    E: Environment,
{
    /// Per-room MLS group state
    groups: HashMap<u128, MlsGroup<E>>,
    /// Frame sequencer (assigns log indices)
    sequencer: Sequencer,
    /// Room metadata (for future authorization)
    room_metadata: HashMap<u128, RoomMetadata<E::Instant>>,
}

/// Actions returned by RoomManager for driver to execute
#[derive(Debug, Clone)]
pub enum RoomAction {
    /// Broadcast this frame to all room members
    Broadcast {
        /// Room ID to broadcast to
        room_id: u128,
        /// Frame to broadcast
        frame: Frame,
        /// Whether to exclude the original sender
        exclude_sender: bool,
    },

    /// Persist frame to storage
    PersistFrame {
        /// Room ID
        room_id: u128,
        /// Log index for this frame
        log_index: u64,
        /// Frame to persist
        frame: Frame,
    },

    /// Persist updated MLS state
    PersistMlsState {
        /// Room ID
        room_id: u128,
        /// Updated MLS state to persist
        state: MlsGroupState,
    },

    /// Reject frame (send error to sender)
    Reject {
        /// Sender who should receive the rejection
        sender_id: u64,
        /// Reason for rejection
        reason: String,
    },
}

/// Errors from RoomManager operations
#[derive(Debug, thiserror::Error)]
pub enum RoomError {
    /// MLS validation failed
    #[error("MLS validation failed: {0}")]
    MlsValidation(#[from] MlsError),

    /// Sequencer error occurred
    #[error("Sequencer error: {0}")]
    Sequencing(#[from] SequencerError),

    /// Storage error occurred
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Room does not exist
    #[error("Room not found: {0:032x}")]
    RoomNotFound(u128),

    /// Room already exists
    #[error("Room already exists: {0:032x}")]
    RoomAlreadyExists(u128),
}

impl<E> RoomManager<E>
where
    E: Environment,
{
    /// Create a new RoomManager
    pub fn new() -> Self {
        Self { groups: HashMap::new(), sequencer: Sequencer::new(), room_metadata: HashMap::new() }
    }

    /// Check if a room exists
    pub fn has_room(&self, room_id: u128) -> bool {
        self.room_metadata.contains_key(&room_id)
    }

    /// Creates a room with the specified ID and records the creator for
    /// future authorization checks. Prevents duplicate room creation.
    ///
    /// # Errors
    ///
    /// Returns `RoomError::RoomAlreadyExists` if the room ID already exists.
    pub fn create_room(&mut self, room_id: u128, creator: u64, env: &E) -> Result<(), RoomError> {
        if self.has_room(room_id) {
            return Err(RoomError::RoomAlreadyExists(room_id));
        }

        // Create MLS group with Environment
        // For server-side room creation, we use room_id as member_id (server is initial
        // member)
        let now = env.now();
        let (group, _actions) =
            MlsGroup::new(env.clone(), room_id, creator, now).map_err(RoomError::MlsValidation)?;
        self.groups.insert(room_id, group);

        // Store metadata (placeholder for future auth)
        let metadata = RoomMetadata { creator, created_at: env.now() };
        self.room_metadata.insert(room_id, metadata);

        Ok(())
    }

    /// Process a frame through MLS validation and sequencing
    ///
    /// This method orchestrates the full frame processing pipeline:
    /// 1. Verify room exists (no lazy creation)
    /// 2. Validate frame against MLS state
    /// 3. Sequence the frame (assign log index)
    /// 4. Convert SequencerAction to RoomAction
    /// 5. Return actions for driver to execute
    ///
    /// # Errors
    ///
    /// Returns `RoomError::RoomNotFound` if room doesn't exist.
    /// Returns `RoomError::MlsValidation` if frame fails validation.
    /// Returns `RoomError::Sequencing` if sequencer encounters an error.
    pub fn process_frame(
        &mut self,
        frame: Frame,
        env: &E,
        storage: &impl Storage,
    ) -> Result<Vec<RoomAction>, RoomError> {
        // 1. Room must exist (no lazy creation)
        let room_id = frame.header.room_id();
        let group = self.groups.get(&room_id).ok_or(RoomError::RoomNotFound(room_id))?;

        // 2. Validate frame against MLS state
        group.validate_frame(&frame, storage)?;

        // 3. Sequence the frame (assign log index)
        let sequencer_actions = self.sequencer.process_frame(frame, storage)?;

        // 4. Convert SequencerAction to RoomAction
        let room_actions = sequencer_actions
            .into_iter()
            .map(|action| match action {
                SequencerAction::AcceptFrame { room_id, log_index, frame } => {
                    RoomAction::PersistFrame { room_id, log_index, frame }
                },
                SequencerAction::StoreFrame { room_id, log_index, frame } => {
                    RoomAction::PersistFrame { room_id, log_index, frame }
                },
                SequencerAction::BroadcastToRoom { room_id, frame } => {
                    RoomAction::Broadcast { room_id, frame, exclude_sender: false }
                },
                SequencerAction::RejectFrame { room_id: _, reason, original_frame } => {
                    RoomAction::Reject { sender_id: original_frame.header.sender_id(), reason }
                },
            })
            .collect();

        // TODO: Update MLS state if this was a commit
        // Currently the sequencer validates against MLS state but doesn't update it.
        // We need to:
        // 1. Check if frame is a Commit
        // 2. Call group.apply_commit(&frame, env)
        // 3. Return PersistMlsState action

        Ok(room_actions)
    }
}

impl<E> Default for RoomManager<E>
where
    E: Environment,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<E> std::fmt::Debug for RoomManager<E>
where
    E: Environment,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomManager")
            .field("room_count", &self.room_metadata.len())
            .field("sequencer", &self.sequencer)
            .finish()
    }
}
