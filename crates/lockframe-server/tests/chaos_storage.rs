//! Chaos property tests for Storage implementations
//!
//! These tests verify that storage implementations maintain invariants even
//! when wrapped in `ChaoticStorage`:
//! - Sequential writes succeed or fail atomically (no partial writes)
//! - Reads after successful writes are consistent
//! - MLS state storage is consistent
//! - Pagination boundaries are correct
//! - Atomic write semantics (no corruption or partial frames)

use bytes::Bytes;
use lockframe_core::mls::MlsGroupState;
use lockframe_proto::{Frame, FrameHeader, Opcode};
use lockframe_server::storage::{
    ChaoticStorage, MemoryStorage, RedbStorage, Storage, StorageError,
};
use proptest::prelude::*;
use tempfile::tempdir;

/// Helper to create a test frame
fn create_test_frame(room_id: u128, log_index: u64, payload: Vec<u8>) -> Frame {
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(room_id);
    header.set_sender_id(1);
    header.set_epoch(0);
    header.set_log_index(log_index);

    Frame::new(header, Bytes::from(payload))
}

/// Verify that all stored frames have sequential log indices
fn verify_frame_sequence(storage: &impl Storage, room_id: u128) -> Result<(), StorageError> {
    if let Some(latest) = storage.latest_log_index(room_id)? {
        let frames = storage.load_frames(room_id, 0, (latest + 1) as usize)?;

        for (expected_idx, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header.log_index(), expected_idx as u64,);
        }

        assert_eq!(frames.len() as u64, latest + 1);
    }

    Ok(())
}

#[test]
fn prop_storage_chaos_atomic_writes() {
    proptest!(|(
        failure_rate in 0.0..0.8,
        seed in any::<u64>(),
        room_id in any::<u128>(),
        frame_count in 10usize..100,
    )| {
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);

        let mut successful_writes = 0u64;
        for i in 0..frame_count {
            let frame = create_test_frame(room_id, i as u64, vec![i as u8]);

            match storage.store_frame(room_id, i as u64, &frame) {
                Ok(()) => successful_writes += 1,
                Err(StorageError::Io(_)) => {
                    // Failure is expected: Once a write fails, all subsequent
                    // writes should fail because log_index doesn't match.
                    break;
                }
                Err(e) => {
                    panic!("Unexpected error: {e:?}");
                }
            }
        }

        // ORACLE: If any writes succeeded, verify they're sequential with no gaps
        if successful_writes > 0 {
            verify_frame_sequence(storage.inner(), room_id)
                .expect("Frame sequence verification failed");

            let latest = storage.inner()
                .latest_log_index(room_id)
                .expect("latest_log_index failed");

            prop_assert_eq!(latest, Some(successful_writes - 1));
        }
    });
}

#[test]
fn prop_storage_chaos_read_consistency() {
    proptest!(|(
        failure_rate in 0.0..0.5, // Lower failure rate to get some successful writes
        seed in any::<u64>(),
        room_id in any::<u128>(),
        write_count in 10usize..50,
    )| {
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);

        let mut expected_frames = Vec::new();
        for i in 0..write_count {
            let frame = create_test_frame(room_id, i as u64, vec![i as u8; 16]);

            if storage.store_frame(room_id, i as u64, &frame).is_ok() {
                expected_frames.push(frame);
            } else {
                break; // Sequential writes stopped
            }
        }

        if expected_frames.is_empty() {
            return Ok(()); // All writes failed due to chaos
        }

        // ORACLE: Read back frames multiple times - should be consistent
        let read1 = storage.inner()
            .load_frames(room_id, 0, expected_frames.len())
            .expect("load_frames failed");

        let read2 = storage.inner()
            .load_frames(room_id, 0, expected_frames.len())
            .expect("load_frames failed");

        prop_assert_eq!(read1.len(), expected_frames.len());
        prop_assert_eq!(read1.len(), read2.len());

        for (expected, actual) in expected_frames.iter().zip(read1.iter()) {
            prop_assert_eq!(expected.header.log_index(), actual.header.log_index());
            prop_assert_eq!(expected.payload.len(), actual.payload.len());
        }
    });
}

#[test]
fn prop_storage_chaos_pagination() {
    proptest!(|(
        seed in any::<u64>(),
        room_id in any::<u128>(),
        total_frames in 20usize..100,
        page_size in 5usize..20,
    )| {
        let failure_rate = 0.0; // all frames should be written
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);

        for i in 0..total_frames {
            let frame = create_test_frame(room_id, i as u64, vec![i as u8]);
            storage.store_frame(room_id, i as u64, &frame)
                .expect("store should succeed with 0% failure rate");
        }

        // ORACLE: Load frames in pages and verify completeness
        let mut all_frames = Vec::new();
        let mut offset = 0;

        loop {
            let page = storage.inner()
                .load_frames(room_id, offset, page_size)
                .expect("load_frames failed");

            if page.is_empty() {
                break;
            }

            all_frames.extend(page);
            offset += page_size as u64;

            if all_frames.len() >= total_frames {
                break;
            }
        }

        prop_assert_eq!(all_frames.len(), total_frames);

        for (expected_idx, frame) in all_frames.iter().enumerate() {
            prop_assert_eq!(frame.header.log_index(), expected_idx as u64);
        }
    });
}

#[test]
fn prop_storage_chaos_mls_state_consistency() {
    proptest!(|(
        failure_rate in 0.0..0.9,
        seed in any::<u64>(),
        room_id in any::<u128>(),
        epoch in 0u64..1000,
        member_count in 1usize..10,
    )| {
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);
        let members: Vec<u64> = (0..member_count).map(|i| i as u64).collect();
        let tree_hash = [42u8; 32];

        let state = MlsGroupState::new(
            room_id,
            epoch,
            tree_hash,
            members.clone(),
        );

        let store_result = storage.store_mls_state(room_id, &state);

        if store_result.is_ok() {
            // ORACLE: If store succeeded, load must return same state
            let loaded = storage.inner()
                .load_mls_state(room_id)
                .expect("load_mls_state failed")
                .expect("state must exist after successful store");

            prop_assert_eq!(loaded.epoch, state.epoch);
            prop_assert_eq!(loaded.member_count(), state.member_count());

            for member_id in members {
                prop_assert!(loaded.is_member(member_id));
            }
        }
    });
}

#[test]
fn prop_storage_chaos_mls_state_overwrite() {
    proptest!(|(
        seed in any::<u64>(),
        room_id in any::<u128>(),
        epochs in prop::collection::vec(0u64..1000, 2..10),
    )| {
        let failure_rate = 0.0; // all frames should be written
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);

        let mut last_state = None;

        // Store multiple states (overwrites)
        for (i, epoch) in epochs.iter().enumerate() {
            let state = MlsGroupState::new(
                room_id,
                *epoch,
                [i as u8; 32], // Different tree_hash each time
                vec![i as u64],
            );

            storage.store_mls_state(room_id, &state)
                .expect("store should succeed with 0% failure");

            last_state = Some(state);
        }

        // ORACLE: Only the last state should be retrievable
        let loaded = storage.inner()
            .load_mls_state(room_id)
            .expect("load_mls_state failed")
            .expect("state must exist");

        let expected = last_state.unwrap();

        prop_assert_eq!(loaded.epoch, expected.epoch);
        prop_assert_eq!(loaded.member_count(), expected.member_count());
    });
}

#[test]
fn prop_storage_conflict_detection() {
    proptest!(|(
        seed in any::<u64>(),
        room_id in any::<u128>(),
        initial_frames in 1usize..10,
        gap_size in 1u64..10,
    )| {
        let failure_rate = 0.0; // all frames should be written
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);

        for i in 0..initial_frames {
            let frame = create_test_frame(room_id, i as u64, vec![i as u8]);
            storage.store_frame(room_id, i as u64, &frame)
                .expect("sequential write should succeed");
        }

        let gap_index = initial_frames as u64 + gap_size; // add gap
        let frame = create_test_frame(room_id, gap_index, vec![0xff]);
        let result = storage.store_frame(room_id, gap_index, &frame);

        // ORACLE: Gap must produce Conflict error
        match result {
            Err(StorageError::Conflict { expected, got }) => {
                prop_assert_eq!(expected, initial_frames as u64);
                prop_assert_eq!(got, gap_index);
            }
            Ok(()) => {
                panic!("Gap write should have failed with Conflict error");
            }
            Err(e) => {
                panic!("Expected Conflict error, got: {e:?}");
            }
        }

        // ORACLE: Storage state unchanged after failed write
        verify_frame_sequence(storage.inner(), room_id)
            .expect("Sequence should be unchanged after failed write");

        let latest = storage.inner()
            .latest_log_index(room_id)
            .expect("latest_log_index failed");

        prop_assert_eq!(latest, Some(initial_frames as u64 - 1));
    });
}

#[test]
fn prop_storage_chaos_concurrent_rooms() {
    proptest!(|(
        failure_rate in 0.0..0.5,
        seed in any::<u64>(),
        room_count in 2usize..10,
        frames_per_room in 5usize..20,
    )| {
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);

        let mut room_write_counts = vec![0u64; room_count];

        for room_idx in 0..room_count {
            let room_id = room_idx as u128;

            for frame_idx in 0..frames_per_room {
                let frame = create_test_frame(room_id, frame_idx as u64, vec![frame_idx as u8]);

                if storage.store_frame(room_id, frame_idx as u64, &frame).is_ok() {
                    room_write_counts[room_idx] += 1;
                } else {
                    break; // Sequential writes stopped for this room
                }
            }
        }

        // ORACLE: Each room's frames are independent and sequential
        for room_idx in 0..room_count {
            let room_id = room_idx as u128;
            let expected_count = room_write_counts[room_idx];

            if expected_count > 0 {
                verify_frame_sequence(storage.inner(), room_id)
                    .expect("Frame sequence verification failed");

                let latest = storage.inner()
                    .latest_log_index(room_id)
                    .expect("latest_log_index failed");

                prop_assert_eq!(latest, Some(expected_count - 1));
            }
        }
    });
}

#[test]
fn prop_storage_atomic_writes_no_corruption() {
    proptest!(|(
        write_count in 1usize..50,
        room_id in any::<u128>(),
    )| {
        let storage = MemoryStorage::new();
        let payload_size = 16;

        // Write frames sequentially
        for i in 0..write_count {
            let frame = create_test_frame(room_id, i as u64, vec![i as u8; payload_size]);
            storage.store_frame(room_id, i as u64, &frame)
                .expect("store should succeed");
        }

        // ORACLE: All written frames are readable and valid
        let loaded = storage.load_frames(room_id, 0, write_count + 10)
            .expect("load_frames should succeed");
        prop_assert_eq!(loaded.len(), write_count);

        // ORACLE: No partial or corrupt frames
        for (i, frame) in loaded.iter().enumerate() {
            prop_assert_eq!(frame.header.log_index(), i as u64);
            prop_assert_eq!(frame.payload.len(), payload_size);

            let expected_payload = vec![i as u8; payload_size];
            prop_assert_eq!(frame.payload.as_ref(), expected_payload.as_slice());
        }

        // ORACLE: latest_log_index is consistent
        let latest = storage.latest_log_index(room_id)
            .expect("latest_log_index should succeed");
        prop_assert_eq!(latest, Some(write_count as u64 - 1));
    });
}

#[test]
fn prop_storage_sequential_batch_writes() {
    proptest!(|(
        batch_sizes in prop::collection::vec(1usize..20, 2..5),
        room_id in any::<u128>(),
    )| {
        let storage = MemoryStorage::new();
        let mut total_written = 0usize;

        // Write multiple batches sequentially
        for batch_size in batch_sizes {
            for i in 0..batch_size {
                let idx = total_written + i;
                let frame = create_test_frame(room_id, idx as u64, vec![idx as u8]);
                storage.store_frame(room_id, idx as u64, &frame)
                    .expect("store should succeed");
            }
            total_written += batch_size;
        }

        // ORACLE: All frames from all batches are present
        let loaded = storage.load_frames(room_id, 0, total_written + 10)
            .expect("load_frames should succeed");
        prop_assert_eq!(loaded.len(), total_written);

        // ORACLE: Sequential indices across all batches
        for (i, frame) in loaded.iter().enumerate() {
            prop_assert_eq!(frame.header.log_index(), i as u64);
        }
    });
}

#[test]
fn prop_redb_storage_atomic_writes() {
    let dir = tempdir().unwrap();
    let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

    let config = ProptestConfig::with_cases(32);
    proptest!(config, |(
        room_id in any::<u128>(),
        frame_count in 10usize..50,
    )| {
        for i in 0..frame_count {
            let frame = create_test_frame(room_id, i as u64, vec![i as u8]);
            storage.store_frame(room_id, i as u64, &frame)
                .expect("sequential write should succeed");
        }

        // ORACLE: Verify sequence is intact
        let frames = storage.load_frames(room_id, 0, frame_count + 10).unwrap();
        prop_assert_eq!(frames.len(), frame_count);

        for (i, frame) in frames.iter().enumerate() {
            prop_assert_eq!(frame.header.log_index(), i as u64);
        }

        let latest = storage.latest_log_index(room_id).unwrap();
        prop_assert_eq!(latest, Some(frame_count as u64 - 1));
    });
}

#[test]
fn prop_redb_storage_conflict_detection() {
    let dir = tempdir().unwrap();
    let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

    let config = ProptestConfig::with_cases(32);
    proptest!(config, |(
        room_id in any::<u128>(),
        initial_frames in 1usize..10,
        gap_size in 1u64..10,
    )| {
        for i in 0..initial_frames {
            let frame = create_test_frame(room_id, i as u64, vec![i as u8]);
            storage.store_frame(room_id, i as u64, &frame)
                .expect("sequential write should succeed");
        }

        let gap_index = initial_frames as u64 + gap_size;
        let frame = create_test_frame(room_id, gap_index, vec![0xff]);
        let result = storage.store_frame(room_id, gap_index, &frame);

        match result {
            Err(StorageError::Conflict { expected, got }) => {
                prop_assert_eq!(expected, initial_frames as u64);
                prop_assert_eq!(got, gap_index);
            }
            Ok(()) => panic!("Gap should have failed"),
            Err(e) => panic!("Expected Conflict, got: {e:?}"),
        }
    });
}

#[test]
fn prop_redb_storage_mls_state_consistency() {
    let dir = tempdir().unwrap();
    let storage = RedbStorage::open(dir.path().join("test.redb")).unwrap();

    let config = ProptestConfig::with_cases(32);
    proptest!(config, |(
        room_id in any::<u128>(),
        epoch in 0u64..1000,
        member_count in 1usize..10,
    )| {
        let members: Vec<u64> = (0..member_count).map(|i| i as u64).collect();
        let state = MlsGroupState::new(room_id, epoch, [42u8; 32], members.clone());

        storage.store_mls_state(room_id, &state).unwrap();

        let loaded = storage.load_mls_state(room_id).unwrap().unwrap();

        prop_assert_eq!(loaded.epoch, epoch);
        prop_assert_eq!(loaded.member_count(), member_count);

        for member_id in members {
            prop_assert!(loaded.is_member(member_id));
        }
    });
}
