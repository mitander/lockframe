//! Storage abstraction for Kalandra protocol
//!
//! This module provides a trait-based abstraction for persisting frames and MLS
//! state. The trait is synchronous (no async) to maintain Sans-IO compliance.

mod error;
mod memory;

pub use error::StorageError;
use kalandra_proto::Frame;
pub use memory::MemoryStorage;

use crate::mls::MlsGroupState;

/// Storage abstraction for frames and MLS group state
///
/// This trait must be:
/// - Clone: Can be passed to multiple state machines
/// - Send + Sync: Thread-safe for concurrent access
/// - Synchronous: No async methods (Sans-IO compliance)
///
/// # Clone Semantics
///
/// Implementations typically share internal state via Arc, meaning clones
/// access the same underlying storage. This enables multiple state machines
/// to share one storage instance safely.
///
/// # Panics
///
/// Implementations may panic if internal synchronization primitives are
/// poisoned (a thread panicked while holding a lock). This is acceptable
/// for test/simulation code, but production implementations should handle
/// poisoned mutexes gracefully or use panic-free synchronization.
pub trait Storage: Clone + Send + Sync + 'static {
    /// Store a frame in the room's log at the given index
    ///
    /// # Invariants
    ///
    /// - **Pre**: `log_index` must equal the current length of the room's log
    /// - **Post**: Frame is persisted at `log_index`
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Conflict` if `log_index` doesn't match expected
    /// position (i.e., there's a gap in the sequence).
    fn store_frame(&self, room_id: u128, log_index: u64, frame: &Frame)
    -> Result<(), StorageError>;

    /// Get the latest log index for a room
    ///
    /// Returns `None` if the room doesn't exist or has no frames.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if underlying storage access fails.
    fn latest_log_index(&self, room_id: u128) -> Result<Option<u64>, StorageError>;

    /// Load frames from a room's log
    ///
    /// Returns frames in range `[from, from+limit)`.
    /// If fewer than `limit` frames exist, returns all available frames.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::NotFound` if the room doesn't exist.
    fn load_frames(
        &self,
        room_id: u128,
        from: u64,
        limit: usize,
    ) -> Result<Vec<Frame>, StorageError>;

    /// Store MLS group state for a room
    ///
    /// Overwrites any existing state for this room.
    fn store_mls_state(&self, room_id: u128, state: &MlsGroupState) -> Result<(), StorageError>;

    /// Load MLS group state for a room
    ///
    /// Returns `None` if no state exists for this room.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if underlying storage access fails.
    /// Returns `StorageError::Serialization` if stored data cannot be
    /// deserialized.
    fn load_mls_state(&self, room_id: u128) -> Result<Option<MlsGroupState>, StorageError>;
}
