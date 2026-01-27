//! Server-side frame sequencer with total ordering.
//!
//! Assigns monotonic log indices to frames, enforcing total ordering across
//! all clients in a room. Maintains `next_log_index` per room, cached from
//! storage.
//!
//! Flow: load state from storage, validate frame structure (magic, version,
//! payload size), assign next `log_index`, return sequencing actions.

use std::collections::HashMap;

use lockframe_core::mls::MAX_EPOCH;
use lockframe_proto::{Frame, FrameHeader};
use thiserror::Error;

use crate::storage::{Storage, StorageError};

/// Errors that can occur during sequencing
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SequencerError {
    /// Storage operation failed
    #[error("storage error: {0}")]
    Storage(String),

    /// Frame validation failed
    #[error("validation error: {0}")]
    Validation(String),

    /// Frame was rejected by validator
    #[error("frame rejected: {0}")]
    Rejected(String),
}

impl From<StorageError> for SequencerError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err.to_string())
    }
}

/// Actions returned by the sequencer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequencerAction {
    /// Frame was accepted and sequenced
    AcceptFrame {
        /// Room ID
        room_id: u128,
        /// Assigned log index
        log_index: u64,
        /// Frame with updated header (includes `log_index`)
        frame: Frame,
    },

    /// Frame was rejected (validation failed)
    RejectFrame {
        /// Room ID
        room_id: u128,
        /// Reason for rejection
        reason: String,
        /// Original frame (unchanged)
        original_frame: Frame,
    },

    /// Store this frame to persistence
    StoreFrame {
        /// Room ID
        room_id: u128,
        /// Log index
        log_index: u64,
        /// Frame to store
        frame: Frame,
    },

    /// Broadcast frame to all room subscribers
    BroadcastToRoom {
        /// Room ID
        room_id: u128,
        /// Frame to broadcast
        frame: Frame,
    },
}

/// Per-room sequencer state (cached)
#[derive(Debug, Clone)]
struct RoomSequencer {
    /// Next log index to assign
    next_log_index: u64,
}

/// Server-side frame sequencer
///
/// The Sequencer maintains per-room state (`next_log_index`)
/// and assigns monotonic log indices to incoming frames.
#[derive(Debug)]
pub struct Sequencer {
    /// Per-room state cache
    rooms: HashMap<u128, RoomSequencer>,
}

/// Validate frame structure at API boundary (before processing)
///
/// Checks:
/// - Magic number is correct
/// - Version is supported
/// - Payload size matches header claim
/// - Room ID is non-zero
/// - Epoch is within reasonable bounds
fn validate_frame_structure(frame: &Frame) -> Result<(), SequencerError> {
    if frame.header.magic() != FrameHeader::MAGIC {
        return Err(SequencerError::Validation(format!(
            "invalid magic: got {:#010x}, expected {:#010x}",
            frame.header.magic(),
            FrameHeader::MAGIC
        )));
    }

    if frame.header.version() != FrameHeader::VERSION {
        return Err(SequencerError::Validation(format!(
            "unsupported version: got {}, expected {}",
            frame.header.version(),
            FrameHeader::VERSION
        )));
    }

    if frame.payload.len() != frame.header.payload_size() as usize {
        return Err(SequencerError::Validation(format!(
            "payload size mismatch: header claims {}, actual {}",
            frame.header.payload_size(),
            frame.payload.len()
        )));
    }

    if frame.header.room_id() == 0 {
        return Err(SequencerError::Validation("room_id is zero (uninitialized?)".to_string()));
    }

    if frame.header.epoch() > MAX_EPOCH {
        return Err(SequencerError::Validation(format!(
            "epoch {} exceeds MAX_EPOCH {}",
            frame.header.epoch(),
            MAX_EPOCH
        )));
    }

    Ok(())
}

impl Sequencer {
    /// Create a new sequencer (empty state)
    pub fn new() -> Self {
        Self { rooms: HashMap::new() }
    }

    /// Process an incoming frame and return actions
    ///
    /// # Invariants
    ///
    /// - Pre: Frame header must be valid (magic, version, etc.)
    /// - Pre: Frame must be validated by caller (`RoomManager`)
    /// - Post: If accepted, `frame.log_index` will be set to next available index
    /// - Post: `room.next_log_index` will be incremented
    pub fn process_frame(
        &mut self,
        frame: Frame,
        storage: &impl Storage,
    ) -> Result<Vec<SequencerAction>, SequencerError> {
        validate_frame_structure(&frame)?;

        let room_id = frame.header.room_id();

        // Welcome frames are NOT sequenced. They use recipient_id for point-to-point
        // delivery and are not stored in the log. The driver handles Welcome frames
        // specially (subscribes recipient to room).
        if frame.header.opcode_enum() == Some(lockframe_proto::Opcode::Welcome) {
            // broadcast to room, no sequencing or storage
            return Ok(vec![SequencerAction::BroadcastToRoom { room_id, frame }]);
        }

        if let std::collections::hash_map::Entry::Vacant(e) = self.rooms.entry(room_id) {
            let latest_index = storage.latest_log_index(room_id).map_err(|e| {
                tracing::error!(
                    room_id = %room_id,
                    error = %e,
                    "Failed to load latest_log_index during room initialization"
                );
                e
            })?;

            let next_log_index = latest_index.map_or(0, |i| i + 1);

            tracing::info!(
                room_id = %room_id,
                latest_storage_index = ?latest_index,
                next_log_index,
                "Initializing sequencer for room"
            );

            debug_assert!(
                latest_index.map_or(next_log_index == 0, |i| next_log_index == i + 1)
            );

            tracing::debug!(
                room_id = %room_id,
                next_log_index,
                "Initialized room state from storage"
            );

            e.insert(RoomSequencer { next_log_index });
        }

        let room = self.rooms.get_mut(&room_id).expect("room must exist after initialization");
        let log_index = room.next_log_index;

        room.next_log_index = room.next_log_index.checked_add(1).ok_or_else(|| {
            SequencerError::Validation(format!(
                "log_index overflow for room {room_id}: attempted to increment beyond u64::MAX"
            ))
        })?;

        debug_assert!(room.next_log_index > log_index);

        let sequenced_frame = rebuild_frame_with_index(frame, log_index)?;

        debug_assert_eq!(sequenced_frame.header.log_index(), log_index);

        let frame_for_actions = sequenced_frame;
        Ok(vec![
            SequencerAction::AcceptFrame { room_id, log_index, frame: frame_for_actions.clone() },
            SequencerAction::StoreFrame { room_id, log_index, frame: frame_for_actions.clone() },
            SequencerAction::BroadcastToRoom { room_id, frame: frame_for_actions },
        ])
    }

    /// Next log index that will be assigned (for testing/debugging).
    #[cfg(test)]
    pub fn next_log_index(&self, room_id: u128) -> Option<u64> {
        self.rooms.get(&room_id).map(|r| r.next_log_index)
    }

    /// Forces re-initialization from storage on next frame.
    ///
    /// Called when storage reports a log index conflict, indicating our
    /// in-memory state has drifted from the persisted log (e.g., after
    /// a server restart or concurrent write).
    pub fn clear_room(&mut self, room_id: u128) -> bool {
        self.rooms.remove(&room_id).is_some()
    }

    /// Pre-initialize a room's sequencer state from storage.
    ///
    /// Called during server recovery to restore room state before accepting
    /// connections. After this call, the sequencer is ready to accept frames
    /// for this room without querying storage again.
    ///
    /// If the room is already initialized, this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns error if storage query fails.
    pub fn initialize_room(
        &mut self,
        room_id: u128,
        storage: &impl Storage,
    ) -> Result<(), SequencerError> {
        if self.rooms.contains_key(&room_id) {
            return Ok(());
        }

        let latest_index = storage
            .latest_log_index(room_id)
            .map_err(|e| SequencerError::Storage(e.to_string()))?;

        let next_log_index = latest_index.map_or(0, |i| i + 1);

        tracing::info!(
            room_id = %room_id,
            latest_storage_index = ?latest_index,
            next_log_index,
            "Pre-initializing sequencer for room during recovery"
        );

        self.rooms.insert(room_id, RoomSequencer { next_log_index });

        Ok(())
    }
}

impl Default for Sequencer {
    fn default() -> Self {
        Self::new()
    }
}

/// Rebuild frame with new header containing assigned `log_index`
///
/// This creates a new `FrameHeader` with the updated `log_index` while
/// reusing the payload bytes (zero-copy via `Bytes::clone` which is Arc-based).
fn rebuild_frame_with_index(original: Frame, log_index: u64) -> Result<Frame, SequencerError> {
    let mut new_header = original.header;
    new_header.set_log_index(log_index);

    Ok(Frame::new(new_header, original.payload))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use lockframe_proto::{FrameHeader, Opcode};

    use super::*;
    use crate::storage::MemoryStorage;

    fn create_test_frame(room_id: u128, sender_id: u64, epoch: u64) -> Frame {
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(sender_id);
        header.set_epoch(epoch);

        Frame::new(header, Bytes::from(format!("msg-{sender_id}")))
    }

    #[test]
    fn test_single_frame_sequencing() {
        let mut sequencer = Sequencer::new();
        let storage = MemoryStorage::new();

        let frame = create_test_frame(100, 200, 0);

        let actions = sequencer.process_frame(frame, &storage).expect("sequencing failed");

        assert_eq!(actions.len(), 3);

        // Check AcceptFrame action
        match &actions[0] {
            SequencerAction::AcceptFrame { room_id, log_index, frame } => {
                assert_eq!(*room_id, 100);
                assert_eq!(*log_index, 0);
                assert_eq!(frame.header.log_index(), 0);
            },
            _ => panic!("Expected AcceptFrame"),
        }

        // Check StoreFrame action
        match &actions[1] {
            SequencerAction::StoreFrame { room_id, log_index, .. } => {
                assert_eq!(*room_id, 100);
                assert_eq!(*log_index, 0);
            },
            _ => panic!("Expected StoreFrame"),
        }

        // Check BroadcastToRoom action
        match &actions[2] {
            SequencerAction::BroadcastToRoom { room_id, frame } => {
                assert_eq!(*room_id, 100);
                assert_eq!(frame.header.log_index(), 0);
            },
            _ => panic!("Expected BroadcastToRoom"),
        }
    }

    #[test]
    fn test_sequential_frames() {
        let mut sequencer = Sequencer::new();
        let storage = MemoryStorage::new();

        let room_id = 100;

        // Process 3 frames
        for i in 0..3 {
            let frame = create_test_frame(room_id, 200, 0); // epoch 0
            let actions = sequencer.process_frame(frame, &storage).expect("sequencing failed");

            // Verify log_index is sequential
            match &actions[0] {
                SequencerAction::AcceptFrame { log_index, .. } => {
                    assert_eq!(*log_index, i);
                },
                _ => panic!("Expected AcceptFrame"),
            }

            // Execute StoreFrame action
            for action in actions {
                if let SequencerAction::StoreFrame { room_id, log_index, frame } = action {
                    storage.store_frame(room_id, log_index, &frame).expect("store failed");
                    break;
                }
            }
        }

        // Verify storage has 3 frames with sequential indices
        let frames = storage.load_frames(room_id, 0, 10).expect("load failed");
        assert_eq!(frames.len(), 3);
        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header.log_index(), i as u64);
        }
    }

    #[test]
    fn test_concurrent_rooms() {
        let mut sequencer = Sequencer::new();
        let storage = MemoryStorage::new();

        // Send frames to room 100
        for _ in 0..3 {
            let frame = create_test_frame(100, 300, 0);
            sequencer.process_frame(frame, &storage).expect("sequencing failed");
        }

        // Send frames to room 200
        for _ in 0..5 {
            let frame = create_test_frame(200, 300, 0);
            sequencer.process_frame(frame, &storage).expect("sequencing failed");
        }

        // Verify independent sequencing
        assert_eq!(sequencer.next_log_index(100), Some(3));
        assert_eq!(sequencer.next_log_index(200), Some(5));
    }

    #[test]
    fn test_sequencer_initialize_room() {
        let mut sequencer = Sequencer::new();
        let storage = MemoryStorage::new();
        let room_id = 100u128;

        // Pre-populate storage with 5 frames
        for i in 0..5 {
            let mut frame = create_test_frame(room_id, 200, 0);
            frame.header.set_log_index(i);
            storage.store_frame(room_id, i, &frame).expect("store failed");
        }

        // Initialize sequencer from storage
        sequencer.initialize_room(room_id, &storage).expect("initialize failed");

        // Verify sequencer knows to start at index 5
        assert_eq!(sequencer.next_log_index(room_id), Some(5));

        // Next frame should be assigned index 5
        let frame = create_test_frame(room_id, 200, 0);
        let actions = sequencer.process_frame(frame, &storage).expect("sequencing failed");

        // Should succeed with index 5
        match &actions[0] {
            SequencerAction::AcceptFrame { log_index, .. } => {
                assert_eq!(*log_index, 5);
            },
            _ => panic!("Expected AcceptFrame"),
        }
    }

    #[test]
    fn test_sequencer_initialize_empty_room() {
        let mut sequencer = Sequencer::new();
        let storage = MemoryStorage::new();
        let room_id = 100u128;

        // No frames in storage, room doesn't exist yet
        // initialize_room should handle this gracefully (next_log_index = 0)
        sequencer.initialize_room(room_id, &storage).expect("initialize failed");

        // Verify sequencer starts at index 0
        assert_eq!(sequencer.next_log_index(room_id), Some(0));

        // First frame should be at index 0
        let frame = create_test_frame(room_id, 200, 0);
        let actions = sequencer.process_frame(frame, &storage).expect("sequencing failed");

        match &actions[0] {
            SequencerAction::AcceptFrame { log_index, .. } => {
                assert_eq!(*log_index, 0);
            },
            _ => panic!("Expected AcceptFrame"),
        }
    }

    #[test]
    fn test_sequencer_initialize_idempotent() {
        let mut sequencer = Sequencer::new();
        let storage = MemoryStorage::new();
        let room_id = 100u128;

        // Pre-populate storage with 5 frames
        for i in 0..5 {
            let mut frame = create_test_frame(room_id, 200, 0);
            frame.header.set_log_index(i);
            storage.store_frame(room_id, i, &frame).expect("store failed");
        }

        // Initialize twice (should be idempotent)
        sequencer.initialize_room(room_id, &storage).expect("first initialize failed");
        sequencer.initialize_room(room_id, &storage).expect("second initialize failed");

        // Verify sequencer state is correct
        assert_eq!(sequencer.next_log_index(room_id), Some(5));

        // Should still work correctly
        let frame = create_test_frame(room_id, 200, 0);
        let actions = sequencer.process_frame(frame, &storage).expect("sequencing failed");

        match &actions[0] {
            SequencerAction::AcceptFrame { log_index, .. } => {
                assert_eq!(*log_index, 5);
            },
            _ => panic!("Expected AcceptFrame"),
        }
    }
}
