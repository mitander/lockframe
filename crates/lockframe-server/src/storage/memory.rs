#![allow(clippy::disallowed_types, reason = "Synchronous in-memory operations only")]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use lockframe_core::mls::MlsGroupState;
use lockframe_proto::Frame;

use super::{Storage, StorageError, StoredRoomMetadata};

/// In-memory storage implementation for testing and simulation
///
/// Uses `HashMap` for fast lookups and Vec for ordered frame storage. All state
/// is wrapped in Arc<Mutex<>> to allow Clone and concurrent access. Thread-safe
/// through Mutex, but uses `lock().expect()` which will panic if the mutex is
/// poisoned - acceptable for test code. All operations are O(1) except
/// `load_frames` which is O(limit).
#[derive(Clone)]
pub struct MemoryStorage {
    inner: Arc<Mutex<MemoryStorageInner>>,
}

struct MemoryStorageInner {
    /// Room metadata (creator, `created_at`)
    rooms: HashMap<u128, StoredRoomMetadata>,

    /// Frames organized by room, stored in `log_index` order
    frames: HashMap<u128, Vec<Frame>>,

    /// MLS group state per room
    mls_states: HashMap<u128, MlsGroupState>,

    /// `GroupInfo` for external joiners, maps `room_id` -> (epoch,
    /// `group_info_bytes`)
    group_infos: HashMap<u128, (u64, Vec<u8>)>,
}

impl MemoryStorage {
    /// Create a new empty `MemoryStorage`
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryStorageInner {
                rooms: HashMap::new(),
                frames: HashMap::new(),
                mls_states: HashMap::new(),
                group_infos: HashMap::new(),
            })),
        }
    }

    /// Number of rooms with stored frames.
    ///
    /// Useful for debugging and testing.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (a thread panicked while
    /// holding the lock). This is acceptable for test/simulation code.
    #[allow(clippy::expect_used)]
    pub fn room_count(&self) -> usize {
        self.inner.lock().expect("Mutex poisoned").frames.len()
    }

    /// Total number of frames across all rooms.
    ///
    /// Useful for debugging and testing.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (a thread panicked while
    /// holding the lock). This is acceptable for test/simulation code.
    #[allow(clippy::expect_used)]
    pub fn total_frame_count(&self) -> usize {
        let inner = self.inner.lock().expect("Mutex poisoned");
        inner.frames.values().map(std::vec::Vec::len).sum()
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl Storage for MemoryStorage {
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn store_frame(
        &self,
        room_id: u128,
        log_index: u64,
        frame: &Frame,
    ) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().expect("Mutex poisoned");

        let frames = inner.frames.entry(room_id).or_default();

        let expected_index = frames.len() as u64;
        debug_assert!(frames.len() < u64::MAX as usize);

        if log_index != expected_index {
            return Err(StorageError::Conflict { expected: expected_index, got: log_index });
        }

        // Clone the frame (in-memory storage owns the data).
        // Note: This clones the entire frame including payload bytes. Production
        // storage (redb) will avoid this by storing serialized bytes directly.
        // The payload clone is cheap (Arc increment via Bytes) but header is copied.
        frames.push(frame.clone());

        debug_assert_eq!(frames.len() as u64 - 1, log_index);
        debug_assert_eq!(frames[log_index as usize].header.log_index(), log_index);

        Ok(())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn latest_log_index(&self, room_id: u128) -> Result<Option<u64>, StorageError> {
        let inner = self.inner.lock().expect("Mutex poisoned");

        Ok(inner.frames.get(&room_id).and_then(|frames| {
            if frames.is_empty() { None } else { Some(frames.len() as u64 - 1) }
        }))
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn load_frames(
        &self,
        room_id: u128,
        from: u64,
        limit: usize,
    ) -> Result<Vec<Frame>, StorageError> {
        let inner = self.inner.lock().expect("Mutex poisoned");

        let frames = inner
            .frames
            .get(&room_id)
            .ok_or(StorageError::NotFound { room_id, log_index: from })?;

        let start = from as usize;
        let end = (start + limit).min(frames.len());

        if start > frames.len() {
            return Ok(Vec::new());
        }

        Ok(frames[start..end].to_vec())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn store_mls_state(&self, room_id: u128, state: &MlsGroupState) -> Result<(), StorageError> {
        self.inner.lock().expect("Mutex poisoned").mls_states.insert(room_id, state.clone());

        Ok(())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn load_mls_state(&self, room_id: u128) -> Result<Option<MlsGroupState>, StorageError> {
        let inner = self.inner.lock().expect("Mutex poisoned");

        Ok(inner.mls_states.get(&room_id).cloned())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn store_group_info(
        &self,
        room_id: u128,
        epoch: u64,
        group_info: &[u8],
    ) -> Result<(), StorageError> {
        self.inner
            .lock()
            .expect("Mutex poisoned")
            .group_infos
            .insert(room_id, (epoch, group_info.to_vec()));

        Ok(())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn load_group_info(&self, room_id: u128) -> Result<Option<(u64, Vec<u8>)>, StorageError> {
        let inner = self.inner.lock().expect("Mutex poisoned");

        Ok(inner.group_infos.get(&room_id).cloned())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn list_rooms(&self) -> Result<Vec<u128>, StorageError> {
        let inner = self.inner.lock().expect("Mutex poisoned");
        Ok(inner.rooms.keys().copied().collect())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn create_room(
        &self,
        room_id: u128,
        metadata: &StoredRoomMetadata,
    ) -> Result<(), StorageError> {
        self.inner
            .lock()
            .expect("Mutex poisoned")
            .rooms
            .entry(room_id)
            .or_insert_with(|| metadata.clone());
        Ok(())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    #[allow(clippy::expect_used)]
    fn load_room_metadata(
        &self,
        room_id: u128,
    ) -> Result<Option<StoredRoomMetadata>, StorageError> {
        Ok(self.inner.lock().expect("Mutex poisoned").rooms.get(&room_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use lockframe_proto::{Frame, FrameHeader, Opcode};

    use super::*;

    fn create_test_frame(room_id: u128, log_index: u64) -> Frame {
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_log_index(log_index);

        Frame::new(header, Bytes::new())
    }

    #[test]
    fn test_new_storage_is_empty() {
        let storage = MemoryStorage::new();
        assert_eq!(storage.room_count(), 0);
        assert_eq!(storage.total_frame_count(), 0);
    }

    #[test]
    fn test_latest_log_index_empty_room() {
        let storage = MemoryStorage::new();
        let result = storage.latest_log_index(100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_store_and_retrieve_frame() {
        let storage = MemoryStorage::new();
        let room_id = 100;
        let frame = create_test_frame(room_id, 0);

        // Store first frame
        storage.store_frame(room_id, 0, &frame).expect("store failed");

        // Check latest index
        assert_eq!(storage.latest_log_index(room_id).expect("query failed"), Some(0));

        // Load frame back
        let frames = storage.load_frames(room_id, 0, 10).expect("load failed");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].header.log_index(), 0);
    }

    #[test]
    fn test_sequential_frames() {
        let storage = MemoryStorage::new();
        let room_id = 100;

        // Store 10 frames sequentially
        for i in 0..10 {
            let frame = create_test_frame(room_id, i);
            storage.store_frame(room_id, i, &frame).expect("store failed");
        }

        // Check latest index
        assert_eq!(storage.latest_log_index(room_id).expect("query failed"), Some(9));

        // Load all frames
        let frames = storage.load_frames(room_id, 0, 100).expect("load failed");
        assert_eq!(frames.len(), 10);

        // Verify sequential log_index
        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header.log_index(), i as u64);
        }
    }

    #[test]
    fn test_conflict_on_gap() {
        let storage = MemoryStorage::new();
        let room_id = 100;

        let frame0 = create_test_frame(room_id, 0);
        let frame2 = create_test_frame(room_id, 2); // Gap!

        storage.store_frame(room_id, 0, &frame0).expect("store failed");

        // Try to store frame at index 2 (should fail)
        let result = storage.store_frame(room_id, 2, &frame2);
        assert!(result.is_err());

        match result {
            Err(StorageError::Conflict { expected, got }) => {
                assert_eq!(expected, 1);
                assert_eq!(got, 2);
            },
            _ => {
                panic!("Expected Conflict error");
            },
        }
    }

    #[test]
    fn test_load_frames_pagination() {
        let storage = MemoryStorage::new();
        let room_id = 100;

        // Store 20 frames
        for i in 0..20 {
            let frame = create_test_frame(room_id, i);
            storage.store_frame(room_id, i, &frame).expect("store failed");
        }

        // Load first 10
        let batch1 = storage.load_frames(room_id, 0, 10).expect("load failed");
        assert_eq!(batch1.len(), 10);
        assert_eq!(batch1[0].header.log_index(), 0);
        assert_eq!(batch1[9].header.log_index(), 9);

        // Load next 10
        let batch2 = storage.load_frames(room_id, 10, 10).expect("load failed");
        assert_eq!(batch2.len(), 10);
        assert_eq!(batch2[0].header.log_index(), 10);
        assert_eq!(batch2[9].header.log_index(), 19);
    }

    #[test]
    fn test_load_frames_beyond_end() {
        let storage = MemoryStorage::new();
        let room_id = 100;

        // Store 5 frames
        for i in 0..5 {
            let frame = create_test_frame(room_id, i);
            storage.store_frame(room_id, i, &frame).expect("store failed");
        }

        // Try to load 10 (should only get 5)
        let frames = storage.load_frames(room_id, 0, 10).expect("load failed");
        assert_eq!(frames.len(), 5);

        // Load from index 10 (beyond end)
        let frames = storage.load_frames(room_id, 10, 10).expect("load failed");
        assert_eq!(frames.len(), 0);
    }

    #[test]
    fn test_multiple_rooms() {
        let storage = MemoryStorage::new();

        // Store frames in room 100
        for i in 0..5 {
            let frame = create_test_frame(100, i);
            storage.store_frame(100, i, &frame).expect("store failed");
        }

        // Store frames in room 200
        for i in 0..3 {
            let frame = create_test_frame(200, i);
            storage.store_frame(200, i, &frame).expect("store failed");
        }

        assert_eq!(storage.room_count(), 2);
        assert_eq!(storage.total_frame_count(), 8);

        assert_eq!(storage.latest_log_index(100).expect("query failed"), Some(4));
        assert_eq!(storage.latest_log_index(200).expect("query failed"), Some(2));
    }

    #[test]
    fn test_mls_state_storage() {
        let storage = MemoryStorage::new();
        let room_id = 100;

        // Initially no state
        assert_eq!(storage.load_mls_state(room_id).expect("load failed"), None);

        // Store state
        let state = MlsGroupState::new(room_id, 5, [42u8; 32], vec![100, 200, 300]);
        storage.store_mls_state(room_id, &state).expect("store failed");

        // Load state back
        let loaded =
            storage.load_mls_state(room_id).expect("load failed").expect("state should exist");

        assert_eq!(loaded.room_id, room_id);
        assert_eq!(loaded.epoch, 5);
        assert_eq!(loaded.tree_hash, [42u8; 32]);
        assert_eq!(loaded.members, vec![100, 200, 300]);
    }

    #[test]
    fn test_mls_state_overwrite() {
        let storage = MemoryStorage::new();
        let room_id = 100;

        // Store initial state
        let state1 = MlsGroupState::new(room_id, 5, [1u8; 32], vec![100]);
        storage.store_mls_state(room_id, &state1).expect("store failed");

        // Overwrite with new state
        let state2 = MlsGroupState::new(room_id, 6, [2u8; 32], vec![100, 200]);
        storage.store_mls_state(room_id, &state2).expect("store failed");

        // Load should return latest state
        let loaded =
            storage.load_mls_state(room_id).expect("load failed").expect("state should exist");

        assert_eq!(loaded.epoch, 6);
        assert_eq!(loaded.members, vec![100, 200]);
    }

    #[test]
    fn test_list_rooms() {
        let storage = MemoryStorage::new();

        // Initially empty
        assert_eq!(storage.list_rooms().unwrap(), vec![]);

        // Create rooms explicitly
        for room_id in [100u128, 200, 300] {
            let metadata = StoredRoomMetadata { creator: room_id as u64, created_at_secs: 0 };
            storage.create_room(room_id, &metadata).unwrap();
        }

        // Should list all three rooms (even without frames)
        let mut rooms = storage.list_rooms().unwrap();
        rooms.sort_unstable();
        assert_eq!(rooms, vec![100, 200, 300]);
    }

    #[test]
    fn test_create_room() {
        let storage = MemoryStorage::new();
        let room_id = 100u128;
        let metadata = StoredRoomMetadata { creator: 42, created_at_secs: 1_234_567_890 };

        storage.create_room(room_id, &metadata).unwrap();

        let loaded = storage.load_room_metadata(room_id).unwrap().unwrap();
        assert_eq!(loaded.creator, 42);
        assert_eq!(loaded.created_at_secs, 1_234_567_890);
    }

    #[test]
    fn test_create_room_idempotent() {
        let storage = MemoryStorage::new();
        let room_id = 100u128;
        let metadata1 = StoredRoomMetadata { creator: 42, created_at_secs: 100 };
        let metadata2 = StoredRoomMetadata { creator: 99, created_at_secs: 200 };

        storage.create_room(room_id, &metadata1).unwrap();
        storage.create_room(room_id, &metadata2).unwrap(); // Should not overwrite

        let loaded = storage.load_room_metadata(room_id).unwrap().unwrap();
        assert_eq!(loaded.creator, 42); // Original creator preserved
    }

    #[test]
    fn test_load_room_metadata_not_found() {
        let storage = MemoryStorage::new();
        assert!(storage.load_room_metadata(999).unwrap().is_none());
    }
}
