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
    /// Per-room MLS group state
    groups: HashMap<u128, MlsGroup<E>>,
    /// Frame sequencer (assigns log indices)
    #[allow(dead_code)] // Will be used in Task 2.3
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

    /// Create a new room with authorization metadata
    ///
    /// Creates a room with the specified ID and records the creator for
    /// future authorization checks. Prevents duplicate room creation.
    ///
    /// # Arguments
    ///
    /// * `room_id` - Unique identifier for the room (128-bit)
    /// * `creator` - User ID of the room creator
    /// * `env` - Environment for time and crypto operations
    ///
    /// # Invariants
    ///
    /// - **Pre:** `!self.has_room(room_id)`
    /// - **Post:** `self.has_room(room_id) == true`
    /// - **Post:** `self.room_metadata[room_id].creator == creator`
    ///
    /// # Errors
    ///
    /// Returns `RoomError::RoomAlreadyExists` if the room ID already exists.
    ///
    /// # Example
    ///
    /// ```
    /// # use kalandra_core::room_manager::{RoomManager, RoomError};
    /// # use kalandra_core::env::Environment;
    /// # #[derive(Clone)]
    /// # struct TestEnv;
    /// # impl Environment for TestEnv {
    /// #     type Instant = std::time::Instant;
    /// #     fn now(&self) -> Self::Instant { std::time::Instant::now() }
    /// #     fn sleep(&self, d: std::time::Duration) -> impl std::future::Future<Output = ()> + Send { async move { tokio::time::sleep(d).await } }
    /// #     fn random_bytes(&self, buffer: &mut [u8]) { use rand::RngCore; rand::thread_rng().fill_bytes(buffer); }
    /// # }
    /// let env = TestEnv;
    /// let mut manager = RoomManager::new();
    /// let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    /// let creator = 42;
    ///
    /// manager.create_room(room_id, creator, &env)?;
    /// assert!(manager.has_room(room_id));
    /// # Ok::<(), RoomError>(())
    /// ```
    pub fn create_room(&mut self, room_id: u128, creator: u64, env: &E) -> Result<(), RoomError>
    where
        E::Instant: Into<std::time::Instant>,
    {
        // Prevent duplicate rooms
        if self.has_room(room_id) {
            return Err(RoomError::RoomAlreadyExists(room_id));
        }

        // Create MLS group with Environment
        // For server-side room creation, we use room_id as member_id (server is initial
        // member)
        let now = env.now().into();
        let (group, _actions) =
            MlsGroup::new(env.clone(), room_id, creator, now).map_err(RoomError::MlsValidation)?;
        self.groups.insert(room_id, group);

        // Store metadata (placeholder for future auth)
        let metadata = RoomMetadata { creator, created_at: env.now() };
        self.room_metadata.insert(room_id, metadata);

        Ok(())
    }

    // process_frame() will be added in Task 2.3
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
