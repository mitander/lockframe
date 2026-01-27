//! Storage abstraction for Lockframe protocol
//!
//! Trait-based abstraction for persisting frames and MLS state. The trait is
//! synchronous (no async) to maintain a clean synchronous API design.

mod chaotic;
mod error;
mod memory;
mod redb;

pub use chaotic::ChaoticStorage;
pub use error::StorageError;
use lockframe_core::mls::MlsGroupState;
use lockframe_proto::Frame;
pub use memory::MemoryStorage;
use serde::{Deserialize, Serialize};

pub use self::redb::RedbStorage;

/// Metadata about a room stored in the ROOMS table.
///
/// This is persisted separately from frames to survive frame deletion
/// (e.g., retention policies) and enable O(rooms) enumeration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRoomMetadata {
    /// User ID who created the room.
    pub creator: u64,
    /// Unix timestamp (seconds) when room was created.
    pub created_at_secs: u64,
}

/// Storage abstraction for frames and MLS group state
///
/// Must be Clone (can be passed to multiple state machines), Send + Sync
/// (thread-safe), and synchronous (no async methods). Implementations typically
/// share internal state via Arc, so clones access the same underlying storage.
///
/// # Panics
///
/// Implementations may panic if internal synchronization primitives are
/// poisoned (a thread panicked while holding a lock). Acceptable for
/// test/simulation code, but production implementations should handle poisoned
/// mutexes gracefully.
pub trait Storage: Clone + Send + Sync + 'static {
    /// Store a frame in the room's log at the given index
    ///
    /// # Invariants
    ///
    /// - Pre: `log_index` must equal the current length of the room's log
    /// - Post: Frame is persisted at `log_index`
    fn store_frame(&self, room_id: u128, log_index: u64, frame: &Frame)
    -> Result<(), StorageError>;

    /// Latest log index for a room. `None` if no frames stored.
    ///
    /// Returns `None` if the room doesn't exist or has no frames.
    fn latest_log_index(&self, room_id: u128) -> Result<Option<u64>, StorageError>;

    /// Load frames from a room's log
    ///
    /// Returns frames in range `[from, from+limit)`.
    /// If fewer than `limit` frames exist, returns all available frames.
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
    fn load_mls_state(&self, room_id: u128) -> Result<Option<MlsGroupState>, StorageError>;

    /// Store GroupInfo for external joiners.
    ///
    /// GroupInfo is updated after each commit so external joiners have
    /// current group state for creating external commits.
    fn store_group_info(
        &self,
        room_id: u128,
        epoch: u64,
        group_info: &[u8],
    ) -> Result<(), StorageError>;

    /// Load GroupInfo for external joiners.
    ///
    /// Returns GroupInfo `(epoch, group_info_bytes)` or `None` if room has no
    /// group info.
    fn load_group_info(&self, room_id: u128) -> Result<Option<(u64, Vec<u8>)>, StorageError>;

    /// List all room IDs.
    ///
    /// Scans the ROOMS table (not FRAMES) for O(rooms) performance.
    /// Used for server recovery to enumerate rooms on startup.
    /// Order is not guaranteed.
    fn list_rooms(&self) -> Result<Vec<u128>, StorageError>;

    /// Create a room with metadata.
    ///
    /// Called when a room is first created. Idempotent - if room already
    /// exists, this is a no-op (does not update metadata).
    fn create_room(&self, room_id: u128, metadata: &StoredRoomMetadata)
    -> Result<(), StorageError>;

    /// Load room metadata.
    ///
    /// Returns `None` if room doesn't exist in the ROOMS table.
    fn load_room_metadata(&self, room_id: u128)
    -> Result<Option<StoredRoomMetadata>, StorageError>;
}
