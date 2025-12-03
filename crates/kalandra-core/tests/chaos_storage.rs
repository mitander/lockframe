//! Chaos property tests for Storage implementations
//!
//! These tests verify that storage implementations maintain invariants even
//! when wrapped in ChaoticStorage:
//! - Sequential writes succeed or fail atomically (no partial writes)
//! - Reads after successful writes are consistent
//! - MLS state storage is consistent
//! - Pagination boundaries are correct

use bytes::Bytes;
use kalandra_core::{
    mls::MlsGroupState,
    storage::{ChaoticStorage, MemoryStorage, Storage, StorageError},
};
use kalandra_proto::{Frame, FrameHeader, Opcode};
use proptest::prelude::*;

/// Create a test frame with specific parameters
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
            assert_eq!(
                frame.header.log_index(),
                expected_idx as u64,
                "Frame index mismatch at position {}",
                expected_idx
            );
        }

        assert_eq!(frames.len() as u64, latest + 1, "Frame count must match latest_index + 1");
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

        // Attempt to write frames sequentially
        for i in 0..frame_count {
            let frame = create_test_frame(room_id, i as u64, vec![i as u8]);

            match storage.store_frame(room_id, i as u64, &frame) {
                Ok(()) => successful_writes += 1,
                Err(StorageError::Io(_)) => {
                    // Chaotic failure - expected
                    // Once a write fails, all subsequent writes should fail
                    // (because log_index doesn't match)
                    break;
                }
                Err(e) => {
                    panic!("Unexpected error: {:?}", e);
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

            prop_assert_eq!(
                latest,
                Some(successful_writes - 1),
                "Latest index must equal number of successful writes - 1"
            );
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

        // Write frames (some may fail)
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

        prop_assert_eq!(
            read1.len(),
            expected_frames.len(),
            "Read count must match write count"
        );

        prop_assert_eq!(read1.len(), read2.len(), "Reads must be consistent");

        // Verify content matches
        for (i, (expected, actual)) in expected_frames.iter().zip(read1.iter()).enumerate() {
            prop_assert_eq!(
                expected.header.log_index(),
                actual.header.log_index(),
                "Frame {} log_index mismatch",
                i
            );

            prop_assert_eq!(
                expected.payload.len(),
                actual.payload.len(),
                "Frame {} payload size mismatch",
                i
            );
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
        // Use 0% failure rate to get all frames written
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), 0.0, seed);

        // Write all frames successfully
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

        prop_assert_eq!(
            all_frames.len(),
            total_frames,
            "Pagination must retrieve all frames"
        );

        // Verify sequential indices
        for (expected_idx, frame) in all_frames.iter().enumerate() {
            prop_assert_eq!(
                frame.header.log_index(),
                expected_idx as u64,
                "Pagination broke sequence at index {}",
                expected_idx
            );
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

        // Create MLS state
        let members: Vec<u64> = (0..member_count).map(|i| i as u64).collect();
        let state = MlsGroupState::new(
            room_id,
            epoch,
            [42u8; 32], // tree_hash
            members.clone(),
            vec![0xde, 0xad], // openmls_state
        );

        // Attempt to store
        let store_result = storage.store_mls_state(room_id, &state);

        if store_result.is_ok() {
            // ORACLE: If store succeeded, load must return same state
            let loaded = storage.inner()
                .load_mls_state(room_id)
                .expect("load_mls_state failed")
                .expect("state must exist after successful store");

            prop_assert_eq!(loaded.epoch, state.epoch, "Epoch mismatch");
            prop_assert_eq!(
                loaded.member_count(),
                state.member_count(),
                "Member count mismatch"
            );

            // Verify all members present
            for member_id in members {
                prop_assert!(
                    loaded.is_member(member_id),
                    "Member {} missing after load",
                    member_id
                );
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
        // Use 0% failure rate for this test
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), 0.0, seed);

        let mut last_state = None;

        // Store multiple states (overwrites)
        for (i, epoch) in epochs.iter().enumerate() {
            let state = MlsGroupState::new(
                room_id,
                *epoch,
                [i as u8; 32], // Different tree_hash each time
                vec![i as u64],
                vec![i as u8],
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

        prop_assert_eq!(loaded.epoch, expected.epoch, "Epoch mismatch");
        prop_assert_eq!(
            loaded.member_count(),
            expected.member_count(),
            "Member count mismatch"
        );
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

        // Write frames to multiple rooms
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

                prop_assert_eq!(
                    latest,
                    Some(expected_count - 1),
                    "Room {} latest index mismatch",
                    room_idx
                );
            }
        }
    });
}
