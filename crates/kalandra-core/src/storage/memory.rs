use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use kalandra_proto::Frame;

use super::{Storage, StorageError};
use crate::mls::MlsGroupState;

/// In-memory storage implementation for testing and simulation
///
/// This implementation uses HashMap for fast lookups and Vec for ordered frame
/// storage. All state is wrapped in Arc<Mutex<>> to allow Clone and concurrent
/// access.
///
/// # Thread Safety
///
/// This implementation is thread-safe through Mutex. However, it uses
/// `lock().expect()` which will panic if the mutex is poisoned (a thread
/// panicked while holding the lock). This is acceptable for test code.
///
/// # Performance
///
/// - store_frame: O(1) amortized
/// - latest_log_index: O(1)
/// - load_frames: O(limit)
/// - store_mls_state: O(1)
/// - load_mls_state: O(1)
#[derive(Clone)]
pub struct MemoryStorage {
    inner: Arc<Mutex<MemoryStorageInner>>,
}

struct MemoryStorageInner {
    /// Frames organized by room, stored in log_index order
    frames: HashMap<u128, Vec<Frame>>,

    /// MLS group state per room
    mls_states: HashMap<u128, MlsGroupState>,
}

impl MemoryStorage {
    /// Create a new empty MemoryStorage
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryStorageInner {
                frames: HashMap::new(),
                mls_states: HashMap::new(),
            })),
        }
    }

    /// Get the number of rooms with stored frames
    ///
    /// Useful for debugging and testing.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (a thread panicked while
    /// holding the lock). This is acceptable for test/simulation code.
    pub fn room_count(&self) -> usize {
        self.inner.lock().expect("MemoryStorage mutex poisoned").frames.len()
    }

    /// Get the total number of frames across all rooms
    ///
    /// Useful for debugging and testing.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (a thread panicked while
    /// holding the lock). This is acceptable for test/simulation code.
    pub fn total_frame_count(&self) -> usize {
        self.inner
            .lock()
            .expect("MemoryStorage mutex poisoned")
            .frames
            .values()
            .map(|frames| frames.len())
            .sum()
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
    fn store_frame(
        &self,
        room_id: u128,
        log_index: u64,
        frame: &Frame,
    ) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().expect("MemoryStorage mutex poisoned");

        let frames = inner.frames.entry(room_id).or_insert_with(Vec::new);

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
    fn latest_log_index(&self, room_id: u128) -> Result<Option<u64>, StorageError> {
        let inner = self.inner.lock().expect("MemoryStorage mutex poisoned");

        Ok(inner.frames.get(&room_id).and_then(|frames| {
            if frames.is_empty() { None } else { Some(frames.len() as u64 - 1) }
        }))
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    fn load_frames(
        &self,
        room_id: u128,
        from: u64,
        limit: usize,
    ) -> Result<Vec<Frame>, StorageError> {
        let inner = self.inner.lock().expect("MemoryStorage mutex poisoned");

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
    fn store_mls_state(&self, room_id: u128, state: &MlsGroupState) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().expect("MemoryStorage mutex poisoned");

        inner.mls_states.insert(room_id, state.clone());

        Ok(())
    }

    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. This is acceptable for test
    /// code.
    fn load_mls_state(&self, room_id: u128) -> Result<Option<MlsGroupState>, StorageError> {
        let inner = self.inner.lock().expect("MemoryStorage mutex poisoned");

        Ok(inner.mls_states.get(&room_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use kalandra_proto::{Frame, FrameHeader, Opcode};

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
            _ => panic!("Expected Conflict error"),
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
        let state =
            MlsGroupState::new(room_id, 5, [42u8; 32], vec![100, 200, 300], vec![1, 2, 3, 4]);
        storage.store_mls_state(room_id, &state).expect("store failed");

        // Load state back
        let loaded =
            storage.load_mls_state(room_id).expect("load failed").expect("state should exist");

        assert_eq!(loaded.room_id, room_id);
        assert_eq!(loaded.epoch, 5);
        assert_eq!(loaded.tree_hash, [42u8; 32]);
        assert_eq!(loaded.members, vec![100, 200, 300]);
        assert_eq!(loaded.openmls_state, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_mls_state_overwrite() {
        let storage = MemoryStorage::new();
        let room_id = 100;

        // Store initial state
        let state1 = MlsGroupState::new(room_id, 5, [1u8; 32], vec![100], vec![]);
        storage.store_mls_state(room_id, &state1).expect("store failed");

        // Overwrite with new state
        let state2 = MlsGroupState::new(room_id, 6, [2u8; 32], vec![100, 200], vec![]);
        storage.store_mls_state(room_id, &state2).expect("store failed");

        // Load should return latest state
        let loaded =
            storage.load_mls_state(room_id).expect("load failed").expect("state should exist");

        assert_eq!(loaded.epoch, 6);
        assert_eq!(loaded.members, vec![100, 200]);
    }
}
