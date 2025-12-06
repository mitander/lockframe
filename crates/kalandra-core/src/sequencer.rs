//! Server-side frame sequencer with total ordering
//!
//! The Sequencer is the "brain" of the Kalandra protocol. It assigns monotonic
//! log indices to frames, enforcing total ordering across all clients in a
//! room.
//!
//! # Architecture
//!
//! - **Sans-IO**: Returns actions instead of performing I/O directly
//! - **Deterministic**: Same input frames → same log_index assignment
//! - **Stateful**: Maintains next_log_index per room (cached from Storage)
//!
//! # Flow
//!
//! 1. **Load State**: Get latest log_index from storage
//! 2. **Validate Frame Structure**: Check magic, version, payload size
//! 3. **Sequence**: Assign next log_index to frame
//! 4. **Return Actions**: StoreFrame, BroadcastFrame, etc.

use std::collections::HashMap;

use kalandra_proto::{Frame, FrameHeader};
use thiserror::Error;

use crate::{
    mls::MAX_EPOCH,
    storage::{Storage, StorageError},
};

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
        SequencerError::Storage(err.to_string())
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
        /// Frame with updated header (includes log_index)
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
/// The Sequencer maintains per-room state (next_log_index)
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

    // Check epoch is within reasonable bounds
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
    /// - **Pre**: Frame header must be valid (magic, version, etc.)
    /// - **Pre**: Frame must be validated by caller (RoomManager)
    /// - **Post**: If accepted, frame.log_index will be set to next available
    ///   index
    /// - **Post**: room.next_log_index will be incremented
    ///
    /// # Errors
    ///
    /// Returns `SequencerError` if storage access fails or validation errors.
    pub fn process_frame(
        &mut self,
        frame: Frame,
        storage: &impl Storage,
    ) -> Result<Vec<SequencerAction>, SequencerError> {
        validate_frame_structure(&frame)?;

        let room_id = frame.header.room_id();

        if !self.rooms.contains_key(&room_id) {
            let latest_index = storage.latest_log_index(room_id).map_err(|e| {
                tracing::error!(
                    room_id = %room_id,
                    error = %e,
                    "Failed to load latest_log_index during room initialization"
                );
                e
            })?;

            let next_log_index = latest_index.map(|i| i + 1).unwrap_or(0);

            debug_assert!(
                latest_index.map(|i| next_log_index == i + 1).unwrap_or(next_log_index == 0)
            );

            tracing::debug!(
                room_id = %room_id,
                next_log_index,
                "Initialized room state from storage"
            );

            self.rooms.insert(room_id, RoomSequencer { next_log_index });
        }

        let room = self.rooms.get_mut(&room_id).expect("room must exist after initialization");

        // MLS validation is now handled by RoomManager before calling this method
        // Sequencer only assigns log indices

        let log_index = room.next_log_index;

        room.next_log_index = room.next_log_index.checked_add(1).ok_or_else(|| {
            SequencerError::Validation(format!(
                "log_index overflow for room {}: attempted to increment beyond u64::MAX",
                room_id
            ))
        })?;

        debug_assert!(room.next_log_index > log_index);

        let sequenced_frame = rebuild_frame_with_index(frame, log_index)?;

        debug_assert_eq!(sequenced_frame.header.log_index(), log_index);

        // Return actions (driver executes them)
        // Note: Frame clones are cheap - payload is Arc-based (Bytes), only header is
        // copied
        let frame_for_actions = sequenced_frame;
        Ok(vec![
            SequencerAction::AcceptFrame { room_id, log_index, frame: frame_for_actions.clone() },
            SequencerAction::StoreFrame { room_id, log_index, frame: frame_for_actions.clone() },
            SequencerAction::BroadcastToRoom { room_id, frame: frame_for_actions },
        ])
    }

    /// Get the next log index for a room (for testing/debugging)
    #[cfg(test)]
    pub fn next_log_index(&self, room_id: u128) -> Option<u64> {
        self.rooms.get(&room_id).map(|r| r.next_log_index)
    }
}

impl Default for Sequencer {
    fn default() -> Self {
        Self::new()
    }
}

/// Rebuild frame with new header containing assigned log_index
///
/// This creates a new FrameHeader with the updated log_index while
/// reusing the payload bytes (zero-copy via Bytes::clone which is Arc-based).
///
/// # Errors
///
/// This function currently cannot fail but returns Result for API consistency.
/// Future versions may add validation that can fail.
fn rebuild_frame_with_index(original: Frame, log_index: u64) -> Result<Frame, SequencerError> {
    let mut new_header = original.header;
    new_header.set_log_index(log_index);

    // Reuse payload bytes (Bytes::clone is cheap - Arc increment)
    Ok(Frame::new(new_header, original.payload.clone()))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use kalandra_proto::{FrameHeader, Opcode};

    use super::*;
    use crate::storage::MemoryStorage;

    fn create_test_frame(room_id: u128, sender_id: u64, epoch: u64) -> Frame {
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(sender_id);
        header.set_epoch(epoch);

        Frame::new(header, Bytes::from(format!("msg-{}", sender_id)))
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
}
