//! Room Manager
//!
//! Routes frames between clients and assigns log indices for total ordering.
//! The server is a routing-only node - it does NOT participate in MLS.
//! Clients own the MLS group state; the server just sequences and broadcasts.
//!
//! Rooms must be explicitly created (no lazy creation) to prevent accidental
//! rooms and enable future auth. RoomMetadata is an extension point for
//! permissions/roles.

use std::collections::HashMap;

use lockframe_core::env::Environment;
use lockframe_proto::Frame;

use crate::{
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

/// Routes frames between clients, assigns log indices.
/// Server is routing-only - does NOT participate in MLS.
///
/// Generic over `I` (Instant type) to support virtual time in tests.
pub struct RoomManager<I = std::time::Instant> {
    /// Frame sequencer (assigns log indices)
    sequencer: Sequencer,
    /// Room metadata (for future authorization)
    room_metadata: HashMap<u128, RoomMetadata<I>>,
}

/// Actions returned by RoomManager for driver to execute.
///
/// Generic over `I` (Instant type) to support virtual time in tests.
#[derive(Debug, Clone)]
pub enum RoomAction<I = std::time::Instant> {
    /// Broadcast this frame to all room members
    Broadcast {
        /// Room ID to broadcast to
        room_id: u128,
        /// Frame to broadcast
        frame: Frame,
        /// Whether to exclude the original sender
        exclude_sender: bool,
        /// When the frame was processed by the server
        processed_at: I,
    },

    /// Persist frame to storage
    PersistFrame {
        /// Room ID
        room_id: u128,
        /// Log index for this frame
        log_index: u64,
        /// Frame to persist
        frame: Frame,
        /// When the frame was processed by the server
        processed_at: I,
    },

    /// Reject frame (send error to sender)
    Reject {
        /// Sender who should receive the rejection
        sender_id: u64,
        /// Reason for rejection
        reason: String,
        /// When the rejection occurred
        processed_at: I,
    },

    /// Send sync response to client
    SendSyncResponse {
        /// Sender to reply to
        sender_id: u64,
        /// Room ID the sync is for
        room_id: u128,
        /// Raw frame bytes to send (each frame serialized)
        frames: Vec<Vec<u8>>,
        /// Whether more frames are available
        has_more: bool,
        /// When the response was prepared
        processed_at: I,
    },
}

/// Errors from RoomManager operations
#[derive(Debug, thiserror::Error)]
pub enum RoomError {
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

impl<I: Copy> RoomManager<I> {
    /// Create a new RoomManager
    pub fn new() -> Self {
        Self { sequencer: Sequencer::new(), room_metadata: HashMap::new() }
    }

    /// Check if a room exists
    pub fn has_room(&self, room_id: u128) -> bool {
        self.room_metadata.contains_key(&room_id)
    }

    /// Creates a room with the specified ID and records the creator for
    /// future authorization checks. Prevents duplicate room creation.
    ///
    /// Note: The server does NOT create an MLS group - it just tracks metadata.
    /// The server routes frames between clients; the clients own the MLS state.
    pub fn create_room<E: Environment<Instant = I>>(
        &mut self,
        room_id: u128,
        creator: u64,
        env: &E,
    ) -> Result<(), RoomError> {
        if self.has_room(room_id) {
            return Err(RoomError::RoomAlreadyExists(room_id));
        }

        // Store metadata only - server doesn't participate in MLS
        let metadata = RoomMetadata { creator, created_at: env.now() };
        self.room_metadata.insert(room_id, metadata);

        Ok(())
    }

    /// Handle a sync request from a client.
    ///
    /// Loads frames from storage starting at `from_log_index` and returns
    /// a `SendSyncResponse` action for the driver to send back to the client.
    pub fn handle_sync_request<E: Environment<Instant = I>>(
        &self,
        room_id: u128,
        sender_id: u64,
        from_log_index: u64,
        limit: usize,
        env: &E,
        storage: &impl Storage,
    ) -> Result<RoomAction<I>, RoomError> {
        let now = env.now();

        if !self.has_room(room_id) {
            return Err(RoomError::RoomNotFound(room_id));
        }

        let frames = storage.load_frames(room_id, from_log_index, limit)?;

        let frame_bytes: Vec<Vec<u8>> = frames
            .iter()
            .map(|f| {
                let mut buf = Vec::new();
                // Frame encoding should not fail for valid frames
                f.encode(&mut buf).expect("invariant: stored frames are valid");
                buf
            })
            .collect();

        let latest_index = storage.latest_log_index(room_id)?;
        let last_loaded_index = if frames.is_empty() {
            from_log_index.saturating_sub(1)
        } else {
            from_log_index + frames.len() as u64 - 1
        };
        let has_more = latest_index.is_some_and(|latest| last_loaded_index < latest);

        Ok(RoomAction::SendSyncResponse {
            sender_id,
            room_id,
            frames: frame_bytes,
            has_more,
            processed_at: now,
        })
    }

    /// Delegates to [`Sequencer::clear_room`] for recovery from storage
    /// conflicts.
    pub fn clear_room_sequencer(&mut self, room_id: u128) -> bool {
        self.sequencer.clear_room(room_id)
    }

    /// Process a frame through sequencing and routing.
    ///
    /// The server is a routing-only node - it does NOT participate in MLS.
    /// Clients own the MLS group state; the server just:
    /// 1. Verifies room exists (metadata check)
    /// 2. Sequences frames (assigns log index)
    /// 3. Routes frames to room subscribers
    pub fn process_frame<E: Environment<Instant = I>>(
        &mut self,
        frame: Frame,
        env: &E,
        storage: &impl Storage,
    ) -> Result<Vec<RoomAction<I>>, RoomError> {
        let now = env.now();

        // 1. Room must exist (check metadata)
        let room_id = frame.header.room_id();
        if !self.has_room(room_id) {
            return Err(RoomError::RoomNotFound(room_id));
        }

        // 2. Sequence the frame (assign log index)
        let sequencer_actions = self.sequencer.process_frame(frame, storage)?;

        // 3. Convert SequencerAction to RoomAction
        let room_actions: Vec<RoomAction<I>> = sequencer_actions
            .into_iter()
            .filter_map(|action| match action {
                SequencerAction::AcceptFrame { .. } => {
                    // AcceptFrame is just validation, no storage needed
                    // StoreFrame handles the actual persistence
                    None
                },
                SequencerAction::StoreFrame { room_id, log_index, frame } => {
                    Some(RoomAction::PersistFrame { room_id, log_index, frame, processed_at: now })
                },
                SequencerAction::BroadcastToRoom { room_id, frame } => {
                    Some(RoomAction::Broadcast {
                        room_id,
                        frame,
                        exclude_sender: false,
                        processed_at: now,
                    })
                },
                SequencerAction::RejectFrame { room_id: _, reason, original_frame } => {
                    Some(RoomAction::Reject {
                        sender_id: original_frame.header.sender_id(),
                        reason,
                        processed_at: now,
                    })
                },
            })
            .collect();

        Ok(room_actions)
    }
}

impl<I: Copy> Default for RoomManager<I> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: Copy> std::fmt::Debug for RoomManager<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomManager")
            .field("room_count", &self.room_metadata.len())
            .field("sequencer", &self.sequencer)
            .finish()
    }
}
