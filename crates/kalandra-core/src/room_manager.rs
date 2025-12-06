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

use std::{collections::HashMap, marker::PhantomData};

use kalandra_proto::Frame;

use crate::{
    env::Environment,
    mls::{error::MlsError, state::MlsGroupState},
    sequencer::{Sequencer, SequencerError},
    storage::StorageError,
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
    /// Frame sequencer (assigns log indices)
    #[allow(dead_code)] // Will be used in Task 2.3
    sequencer: Sequencer,
    /// Room metadata (for future authorization)
    room_metadata: HashMap<u128, RoomMetadata<E::Instant>>,
    /// Type marker for environment
    _phantom: PhantomData<E>,
    // Note: MlsGroup instances will be stored in HashMap in Task 2.2
    // groups: HashMap<u128, MlsGroup<E>>, // Added in Task 2.2
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
        Self { sequencer: Sequencer::new(), room_metadata: HashMap::new(), _phantom: PhantomData }
    }

    /// Check if a room exists
    pub fn has_room(&self, room_id: u128) -> bool {
        self.room_metadata.contains_key(&room_id)
    }

    // create_room() and process_frame() will be added in Tasks 2.2 and 2.3
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
    E::Instant: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomManager").field("room_count", &self.room_metadata.len()).finish()
    }
}
