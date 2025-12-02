//! Storage error types.
//!
//! Defines errors that can occur during storage operations:
//! - `NotFound`: Requested frame or room doesn't exist
//! - `Conflict`: Log index gap detected (sequencing violation)
//! - `Serialization`: Failed to encode/decode data
//! - `Io`: Underlying storage system errors

use thiserror::Error;

/// Errors that can occur during storage operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Frame or room not found
    #[error("frame not found: room {room_id}, index {log_index}")]
    NotFound {
        /// Room ID that was not found
        room_id: u128,
        /// Log index that was not found
        log_index: u64,
    },

    /// Log index conflict (gap in sequence)
    ///
    /// This error occurs when trying to store a frame at a log_index that
    /// doesn't match the expected next position. For example, storing at
    /// index 5 when the room only has 3 frames (expected index 3).
    #[error("log index conflict: expected {expected}, got {got}")]
    Conflict {
        /// Expected log index (current room length)
        expected: u64,
        /// Provided log index (creates a gap)
        got: u64,
    },

    /// Serialization or deserialization failed
    #[error("serialization error: {0}")]
    Serialization(String),

    /// I/O error (file system, database, etc.)
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<Box<bincode::ErrorKind>> for StorageError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        StorageError::Serialization(err.to_string())
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err.to_string())
    }
}
