//! Redb-backed durable storage implementation.
//!
//! Uses Redb's ACID transactions with Copy-on-Write for crash safety.
//! All state survives server restarts.

use std::{path::Path, sync::Arc};

use lockframe_core::mls::MlsGroupState;
use lockframe_proto::Frame;
use redb::{Database, ReadableTable, TableDefinition};

use super::{Storage, StorageError, StoredRoomMetadata};

/// Table: frames
/// Key: (room_id: u128, log_index: u64) as big-endian bytes [24 bytes]
/// Value: Frame bytes (header + payload concatenated)
const FRAMES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("frames");

/// Table: mls_state
/// Key: room_id as big-endian bytes [16 bytes]
/// Value: CBOR-encoded MlsGroupState
const MLS_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mls_state");

/// Table: group_info
/// Key: room_id as big-endian bytes [16 bytes]
/// Value: epoch (8 bytes BE) + group_info bytes
const GROUP_INFO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("group_info");

/// Table: rooms
/// Key: room_id as big-endian bytes [16 bytes]
/// Value: CBOR-encoded StoredRoomMetadata
const ROOMS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rooms");

/// Durable storage backed by Redb.
///
/// Thread-safe through Redb's internal locking. Clone is cheap (Arc).
#[derive(Clone)]
pub struct RedbStorage {
    db: Arc<Database>,
}

impl RedbStorage {
    /// Open or create a Redb database at the given path.
    ///
    /// Creates tables if they don't exist (FRAMES, MLS_STATE, GROUP_INFO,
    /// ROOMS).
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the database cannot be opened or created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = Database::create(path.as_ref()).map_err(|e| StorageError::Io(e.to_string()))?;

        let txn = db.begin_write().map_err(|e| StorageError::Io(e.to_string()))?;
        {
            let _ = txn.open_table(FRAMES).map_err(|e| StorageError::Io(e.to_string()))?;
            let _ = txn.open_table(MLS_STATE).map_err(|e| StorageError::Io(e.to_string()))?;
            let _ = txn.open_table(GROUP_INFO).map_err(|e| StorageError::Io(e.to_string()))?;
            let _ = txn.open_table(ROOMS).map_err(|e| StorageError::Io(e.to_string()))?;
        }
        txn.commit().map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Compute the next expected log_index for a room.
    fn compute_next_log_index<T: ReadableTable<&'static [u8], &'static [u8]>>(
        &self,
        table: &T,
        room_id: u128,
    ) -> Result<u64, StorageError> {
        match self.compute_latest_log_index(table, room_id)? {
            Some(latest) => Ok(latest + 1),
            None => Ok(0),
        }
    }

    /// Find the latest log_index for a room by scanning keys.
    fn compute_latest_log_index<T: ReadableTable<&'static [u8], &'static [u8]>>(
        &self,
        table: &T,
        room_id: u128,
    ) -> Result<Option<u64>, StorageError> {
        let start_key = encode_frame_key(room_id, 0);
        let end_key = encode_frame_key(room_id, u64::MAX);

        let results = table
            .range(start_key.as_slice()..=end_key.as_slice())
            .map_err(|e| StorageError::Io(e.to_string()))?;

        let mut latest: Option<u64> = None;
        for result in results {
            let (key, _) = result.map_err(|e| StorageError::Io(e.to_string()))?;
            let (_, log_index) = decode_frame_key(key.value());
            latest = Some(log_index);
        }

        Ok(latest)
    }
}

impl Storage for RedbStorage {
    fn store_frame(
        &self,
        room_id: u128,
        log_index: u64,
        frame: &Frame,
    ) -> Result<(), StorageError> {
        let txn = self.db.begin_write().map_err(|e| StorageError::Io(e.to_string()))?;

        {
            let mut table = txn.open_table(FRAMES).map_err(|e| StorageError::Io(e.to_string()))?;

            let expected_index = self.compute_next_log_index(&table, room_id)?;

            if log_index != expected_index {
                return Err(StorageError::Conflict { expected: expected_index, got: log_index });
            }

            let mut frame_bytes = Vec::with_capacity(128 + frame.payload.len());
            frame
                .encode(&mut frame_bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            let key = encode_frame_key(room_id, log_index);
            table
                .insert(key.as_slice(), frame_bytes.as_slice())
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }

        txn.commit().map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(())
    }

    fn latest_log_index(&self, room_id: u128) -> Result<Option<u64>, StorageError> {
        let txn = self.db.begin_read().map_err(|e| StorageError::Io(e.to_string()))?;
        let table = txn.open_table(FRAMES).map_err(|e| StorageError::Io(e.to_string()))?;

        self.compute_latest_log_index(&table, room_id)
    }

    fn load_frames(
        &self,
        room_id: u128,
        from: u64,
        limit: usize,
    ) -> Result<Vec<Frame>, StorageError> {
        let txn = self.db.begin_read().map_err(|e| StorageError::Io(e.to_string()))?;

        let table = txn.open_table(FRAMES).map_err(|e| StorageError::Io(e.to_string()))?;

        let start_key = encode_frame_key(room_id, from);
        let end_key = encode_frame_key(room_id, u64::MAX);

        let results = table
            .range(start_key.as_slice()..=end_key.as_slice())
            .map_err(|e| StorageError::Io(e.to_string()))?;

        let mut frames = Vec::with_capacity(limit);
        for result in results {
            if frames.len() >= limit {
                break;
            }

            let (key, value) = result.map_err(|e| StorageError::Io(e.to_string()))?;
            let (key_room_id, _) = decode_frame_key(key.value());

            if key_room_id != room_id {
                break;
            }

            let frame = Frame::decode(value.value())
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            frames.push(frame);
        }

        Ok(frames)
    }

    fn store_mls_state(&self, room_id: u128, state: &MlsGroupState) -> Result<(), StorageError> {
        let txn = self.db.begin_write().map_err(|e| StorageError::Io(e.to_string()))?;

        {
            let mut table =
                txn.open_table(MLS_STATE).map_err(|e| StorageError::Io(e.to_string()))?;

            let mut bytes = Vec::new();
            ciborium::into_writer(state, &mut bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            let key = encode_room_key(room_id);
            table
                .insert(key.as_slice(), bytes.as_slice())
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }

        txn.commit().map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(())
    }

    fn load_mls_state(&self, room_id: u128) -> Result<Option<MlsGroupState>, StorageError> {
        let txn = self.db.begin_read().map_err(|e| StorageError::Io(e.to_string()))?;

        let table = txn.open_table(MLS_STATE).map_err(|e| StorageError::Io(e.to_string()))?;

        let key = encode_room_key(room_id);

        match table.get(key.as_slice()).map_err(|e| StorageError::Io(e.to_string()))? {
            Some(value) => {
                let state: MlsGroupState = ciborium::from_reader(value.value())
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(state))
            },
            None => Ok(None),
        }
    }

    fn store_group_info(
        &self,
        room_id: u128,
        epoch: u64,
        group_info: &[u8],
    ) -> Result<(), StorageError> {
        let txn = self.db.begin_write().map_err(|e| StorageError::Io(e.to_string()))?;

        {
            let mut table =
                txn.open_table(GROUP_INFO).map_err(|e| StorageError::Io(e.to_string()))?;

            // Format: [epoch: 8 bytes BE][group_info bytes]
            let mut value = Vec::with_capacity(8 + group_info.len());
            value.extend_from_slice(&epoch.to_be_bytes());
            value.extend_from_slice(group_info);

            let key = encode_room_key(room_id);
            table
                .insert(key.as_slice(), value.as_slice())
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }

        txn.commit().map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(())
    }

    fn load_group_info(&self, room_id: u128) -> Result<Option<(u64, Vec<u8>)>, StorageError> {
        let txn = self.db.begin_read().map_err(|e| StorageError::Io(e.to_string()))?;

        let table = txn.open_table(GROUP_INFO).map_err(|e| StorageError::Io(e.to_string()))?;

        let key = encode_room_key(room_id);

        match table.get(key.as_slice()).map_err(|e| StorageError::Io(e.to_string()))? {
            Some(value) => {
                let bytes = value.value();
                if bytes.len() < 8 {
                    return Err(StorageError::Serialization(
                        "group_info value too short".to_string(),
                    ));
                }

                let epoch = u64::from_be_bytes(bytes[..8].try_into().expect("length checked"));
                let group_info = bytes[8..].to_vec();

                Ok(Some((epoch, group_info)))
            },
            None => Ok(None),
        }
    }

    fn list_rooms(&self) -> Result<Vec<u128>, StorageError> {
        let txn = self.db.begin_read().map_err(|e| StorageError::Io(e.to_string()))?;

        let table = txn.open_table(ROOMS).map_err(|e| StorageError::Io(e.to_string()))?;

        let mut rooms = Vec::new();

        for result in table.iter().map_err(|e| StorageError::Io(e.to_string()))? {
            let (key, _) = result.map_err(|e| StorageError::Io(e.to_string()))?;
            let room_id = u128::from_be_bytes(key.value().try_into().expect("key is 16 bytes"));
            rooms.push(room_id);
        }

        Ok(rooms)
    }

    fn create_room(
        &self,
        room_id: u128,
        metadata: &StoredRoomMetadata,
    ) -> Result<(), StorageError> {
        let txn = self.db.begin_write().map_err(|e| StorageError::Io(e.to_string()))?;

        {
            let mut table = txn.open_table(ROOMS).map_err(|e| StorageError::Io(e.to_string()))?;

            let key = encode_room_key(room_id);

            if table.get(key.as_slice()).map_err(|e| StorageError::Io(e.to_string()))?.is_some() {
                return Ok(()); // Already exists, don't overwrite
            }

            let mut bytes = Vec::new();
            ciborium::into_writer(metadata, &mut bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            table
                .insert(key.as_slice(), bytes.as_slice())
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }

        txn.commit().map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(())
    }

    fn load_room_metadata(
        &self,
        room_id: u128,
    ) -> Result<Option<StoredRoomMetadata>, StorageError> {
        let txn = self.db.begin_read().map_err(|e| StorageError::Io(e.to_string()))?;

        let table = txn.open_table(ROOMS).map_err(|e| StorageError::Io(e.to_string()))?;

        let key = encode_room_key(room_id);

        match table.get(key.as_slice()).map_err(|e| StorageError::Io(e.to_string()))? {
            Some(value) => {
                let metadata: StoredRoomMetadata = ciborium::from_reader(value.value())
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(metadata))
            },
            None => Ok(None),
        }
    }
}

/// Encode (room_id, log_index) as 24-byte big-endian key.
///
/// Layout: [room_id: 16 bytes BE][log_index: 8 bytes BE]
/// This ensures lexicographic ordering matches numeric ordering.
fn encode_frame_key(room_id: u128, log_index: u64) -> [u8; 24] {
    let mut key = [0u8; 24];
    key[..16].copy_from_slice(&room_id.to_be_bytes());
    key[16..].copy_from_slice(&log_index.to_be_bytes());
    key
}

/// Decode frame key back to (room_id, log_index).
fn decode_frame_key(key: &[u8]) -> (u128, u64) {
    debug_assert_eq!(key.len(), 24);
    let room_id = u128::from_be_bytes(key[..16].try_into().expect("key length verified"));
    let log_index = u64::from_be_bytes(key[16..].try_into().expect("key length verified"));
    (room_id, log_index)
}

/// Encode room_id as 16-byte big-endian key.
fn encode_room_key(room_id: u128) -> [u8; 16] {
    room_id.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use lockframe_proto::{Frame, FrameHeader, Opcode};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_frame_key_encoding() {
        let room_id: u128 = 0x123456789ABCDEF0_FEDCBA9876543210;
        let log_index: u64 = 42;

        let key = encode_frame_key(room_id, log_index);
        assert_eq!(key.len(), 24);

        let (decoded_room, decoded_index) = decode_frame_key(&key);
        assert_eq!(decoded_room, room_id);
        assert_eq!(decoded_index, log_index);
    }

    #[test]
    fn test_room_key_encoding() {
        let room_id: u128 = 0x123456789ABCDEF0_FEDCBA9876543210;

        let key = encode_room_key(room_id);
        assert_eq!(key.len(), 16);

        let decoded = u128::from_be_bytes(key.try_into().expect("key length verified"));
        assert_eq!(decoded, room_id);
    }

    fn create_test_frame(room_id: u128, log_index: u64, payload: &[u8]) -> Frame {
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(1);
        header.set_epoch(0);
        header.set_log_index(log_index);
        Frame::new(header, Bytes::copy_from_slice(payload))
    }

    #[test]
    fn test_store_frame_sequential() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;

        // Store frames 0, 1, 2
        for i in 0..3 {
            let frame = create_test_frame(room_id, i, &[i as u8; 16]);
            storage.store_frame(room_id, i, &frame).unwrap();
        }

        // Verify latest index
        assert_eq!(storage.latest_log_index(room_id).unwrap(), Some(2));
    }

    #[test]
    fn test_store_frame_conflict() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;

        // Store frame 0
        let frame0 = create_test_frame(room_id, 0, &[0u8; 16]);
        storage.store_frame(room_id, 0, &frame0).unwrap();

        // Try to store frame 2 (gap)
        let frame2 = create_test_frame(room_id, 2, &[2u8; 16]);
        let result = storage.store_frame(room_id, 2, &frame2);

        match result {
            Err(StorageError::Conflict { expected: 1, got: 2 }) => {},
            other => panic!("Expected Conflict error, got: {:?}", other),
        }
    }

    #[test]
    fn test_latest_log_index_empty_room() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        // Room with no frames should return None
        assert_eq!(storage.latest_log_index(999).unwrap(), None);
    }

    #[test]
    fn test_load_frames_pagination() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;

        // Store 20 frames
        for i in 0..20 {
            let frame = create_test_frame(room_id, i, &[i as u8; 16]);
            storage.store_frame(room_id, i, &frame).unwrap();
        }

        // Load first 10
        let batch1 = storage.load_frames(room_id, 0, 10).unwrap();
        assert_eq!(batch1.len(), 10);
        assert_eq!(batch1[0].header.log_index(), 0);
        assert_eq!(batch1[9].header.log_index(), 9);

        // Load next 10
        let batch2 = storage.load_frames(room_id, 10, 10).unwrap();
        assert_eq!(batch2.len(), 10);
        assert_eq!(batch2[0].header.log_index(), 10);
        assert_eq!(batch2[9].header.log_index(), 19);

        // Load beyond end
        let batch3 = storage.load_frames(room_id, 20, 10).unwrap();
        assert_eq!(batch3.len(), 0);
    }

    #[test]
    fn test_load_frames_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;
        let payload = b"hello world";

        let frame = create_test_frame(room_id, 0, payload);
        storage.store_frame(room_id, 0, &frame).unwrap();

        let loaded = storage.load_frames(room_id, 0, 10).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].payload.as_ref(), payload);
        assert_eq!(loaded[0].header.room_id(), room_id);
    }

    #[test]
    fn test_mls_state_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;

        // Initially no state
        assert!(storage.load_mls_state(room_id).unwrap().is_none());

        // Store state
        let state = MlsGroupState::new(
            room_id,
            5,                   // epoch
            [42u8; 32],          // tree_hash
            vec![100, 200, 300], // members
        );
        storage.store_mls_state(room_id, &state).unwrap();

        // Load and verify
        let loaded = storage.load_mls_state(room_id).unwrap().unwrap();
        assert_eq!(loaded.room_id, room_id);
        assert_eq!(loaded.epoch, 5);
        assert_eq!(loaded.tree_hash, [42u8; 32]);
        assert_eq!(loaded.members, vec![100, 200, 300]);
    }

    #[test]
    fn test_mls_state_overwrite() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;

        // Store initial state
        let state1 = MlsGroupState::new(room_id, 1, [1u8; 32], vec![100]);
        storage.store_mls_state(room_id, &state1).unwrap();

        // Overwrite
        let state2 = MlsGroupState::new(room_id, 2, [2u8; 32], vec![100, 200]);
        storage.store_mls_state(room_id, &state2).unwrap();

        // Should get latest
        let loaded = storage.load_mls_state(room_id).unwrap().unwrap();
        assert_eq!(loaded.epoch, 2);
        assert_eq!(loaded.members, vec![100, 200]);
    }

    #[test]
    fn test_group_info_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;
        let epoch = 5u64;
        let group_info = b"group info bytes here";

        // Initially no group info
        assert!(storage.load_group_info(room_id).unwrap().is_none());

        // Store
        storage.store_group_info(room_id, epoch, group_info).unwrap();

        // Load and verify
        let (loaded_epoch, loaded_bytes) = storage.load_group_info(room_id).unwrap().unwrap();
        assert_eq!(loaded_epoch, epoch);
        assert_eq!(loaded_bytes, group_info);
    }

    #[test]
    fn test_group_info_overwrite() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;

        // Store initial
        storage.store_group_info(room_id, 1, b"epoch1").unwrap();

        // Overwrite
        storage.store_group_info(room_id, 2, b"epoch2").unwrap();

        // Should get latest
        let (epoch, bytes) = storage.load_group_info(room_id).unwrap().unwrap();
        assert_eq!(epoch, 2);
        assert_eq!(bytes, b"epoch2");
    }

    #[test]
    fn test_list_rooms() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        assert_eq!(storage.list_rooms().unwrap(), vec![]);

        for room_id in [100u128, 200, 300] {
            let metadata = StoredRoomMetadata { creator: room_id as u64, created_at_secs: 0 };
            storage.create_room(room_id, &metadata).unwrap();
        }

        let mut rooms = storage.list_rooms().unwrap();
        rooms.sort();
        assert_eq!(rooms, vec![100, 200, 300]);
    }

    #[test]
    fn test_create_room() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        let room_id = 100u128;
        let metadata = StoredRoomMetadata { creator: 42, created_at_secs: 1_234_567_890 };

        storage.create_room(room_id, &metadata).unwrap();

        let loaded = storage.load_room_metadata(room_id).unwrap().unwrap();
        assert_eq!(loaded.creator, 42);
        assert_eq!(loaded.created_at_secs, 1_234_567_890);
    }

    #[test]
    fn test_create_room_idempotent() {
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

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
        let dir = tempdir().unwrap();
        let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

        assert!(storage.load_room_metadata(999).unwrap().is_none());
    }
}
