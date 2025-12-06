//! Chaos property tests for Sequencer with failing storage
//!
//! These tests verify that the Sequencer handles storage failures gracefully:
//! - No panics even with high failure rates
//! - Frames that DO succeed have sequential indices (no gaps)
//! - State remains consistent after failures
//! - Errors are properly propagated

use bytes::Bytes;
use kalandra_core::{
    sequencer::Sequencer,
    storage::{ChaoticStorage, MemoryStorage, Storage},
};
use kalandra_proto::{Frame, FrameHeader, Opcode};
use proptest::prelude::*;

/// Create a test frame with specific parameters
fn create_test_frame(room_id: u128, sender_id: u64, epoch: u64, payload: Vec<u8>) -> Frame {
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(room_id);
    header.set_sender_id(sender_id);
    header.set_epoch(epoch);
    header.set_log_index(0); // Will be set by sequencer

    Frame::new(header, Bytes::from(payload))
}

/// Strategy for generating arbitrary frames
fn arbitrary_frame() -> impl Strategy<Value = Frame> {
    (
        any::<u128>(),                              // room_id
        1u64..=1000,                                // sender_id (non-zero)
        0u64..=100,                                 // epoch
        prop::collection::vec(any::<u8>(), 0..256), // payload
    )
        .prop_map(|(room_id, sender_id, epoch, payload)| {
            create_test_frame(room_id, sender_id, epoch, payload)
        })
}

/// Verify that frames stored in a room have sequential indices with no gaps
fn verify_sequential_indices(storage: &impl Storage, room_id: u128) {
    if let Ok(Some(latest)) = storage.latest_log_index(room_id) {
        // Load all frames
        let frames = storage
            .load_frames(room_id, 0, (latest + 1) as usize)
            .expect("load_frames should succeed");

        // Verify sequential indices
        for (expected_index, frame) in frames.iter().enumerate() {
            assert_eq!(
                frame.header.log_index(),
                expected_index as u64,
                "Frame indices must be sequential without gaps"
            );
        }
    }
}

#[test]
fn prop_sequencer_survives_low_chaos() {
    proptest!(|(
        failure_rate in 0.0..0.3,  // Low chaos: 0-30% failures
        seed in any::<u64>(),
        frames in prop::collection::vec(arbitrary_frame(), 1..50)
    )| {
        let inner_storage = MemoryStorage::new();
        let storage = ChaoticStorage::with_seed(inner_storage, failure_rate, seed);
        let mut sequencer = Sequencer::new();

        // Process all frames - some may fail due to storage chaos
        for frame in frames {
            let room_id = frame.header.room_id();
            let _ = sequencer.process_frame(frame, &storage);

            // INVARIANT: Frames that DID succeed must have sequential indices
            verify_sequential_indices(storage.inner(), room_id);
        }
    });
}

#[test]
fn prop_sequencer_survives_high_chaos() {
    proptest!(|(
        failure_rate in 0.7..0.95,  // High chaos: 70-95% failures
        seed in any::<u64>(),
        frames in prop::collection::vec(arbitrary_frame(), 1..50)
    )| {
        let inner_storage = MemoryStorage::new();
        let storage = ChaoticStorage::with_seed(inner_storage, failure_rate, seed);
        let mut sequencer = Sequencer::new();

        // Process all frames - most will fail
        for frame in frames {
            let room_id = frame.header.room_id();
            let _ = sequencer.process_frame(frame, &storage);

            // INVARIANT: Even with high failure rate, no gaps in what DID succeed
            verify_sequential_indices(storage.inner(), room_id);
        }
    });
}

#[test]
fn prop_sequencer_deterministic_under_chaos() {
    proptest!(|(
        failure_rate in 0.0..1.0,
        seed in any::<u64>(),
        frames in prop::collection::vec(arbitrary_frame(), 1..30)
    )| {
        // Run 1: Process frames with chaotic storage
        let storage1 = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);
        let mut sequencer1 = Sequencer::new();

        let results1: Vec<_> = frames
            .iter()
            .map(|f| sequencer1.process_frame(f.clone(), &storage1).is_ok())
            .collect();

        // Run 2: Same seed should produce same failure pattern
        let storage2 = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);
        let mut sequencer2 = Sequencer::new();

        let results2: Vec<_> = frames
            .iter()
            .map(|f| sequencer2.process_frame(f.clone(), &storage2).is_ok())
            .collect();

        // INVARIANT: Deterministic chaos - same seed, same results
        prop_assert_eq!(results1, results2, "Same seed must produce same outcome");
    });
}

#[test]
fn prop_sequencer_never_creates_gaps() {
    proptest!(|(
        failure_rate in 0.0..0.8,
        seed in any::<u64>(),
        room_id in any::<u128>(),
        frame_count in 10usize..100
    )| {
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), failure_rate, seed);
        let mut sequencer = Sequencer::new();

        // Track storage operations for performance oracle
        let mut attempt_count = 0usize;

        // Create frames for single room with incrementing epochs
        for i in 0..frame_count {
            let mut header = FrameHeader::new(Opcode::AppMessage);
            header.set_room_id(room_id);
            header.set_sender_id(1);
            header.set_epoch(0);
            header.set_log_index(0);

            let frame = Frame::new(header, Bytes::from(vec![i as u8]));

            attempt_count += 1;
            let _ = sequencer.process_frame(frame, &storage);
        }

        // ORACLE: Check that all stored frames have sequential indices
        if let Ok(Some(latest)) = storage.inner().latest_log_index(room_id) {
            let frames = storage.inner()
                .load_frames(room_id, 0, (latest + 1) as usize)
                .expect("load should succeed");

            // Verify NO gaps
            for (expected_idx, frame) in frames.iter().enumerate() {
                prop_assert_eq!(
                    frame.header.log_index(),
                    expected_idx as u64,
                    "Gap detected in log indices"
                );
            }

            // Verify indices are exactly [0, 1, 2, ..., latest]
            prop_assert_eq!(
                frames.len() as u64,
                latest + 1,
                "Frame count must match latest index + 1"
            );

            // PERFORMANCE ORACLE: Each frame requires O(1) operations
            // Even with failures, total work should be O(n) not O(n²)
            // We expect at most 3 storage ops per attempt: load_mls_state, store_frame, store_mls_state
            let max_expected_ops = attempt_count * 3;
            let actual_ops = storage.operation_count();

            prop_assert!(
                actual_ops <= max_expected_ops,
                "Performance degradation detected: {} ops for {} attempts (max expected: {})",
                actual_ops,
                attempt_count,
                max_expected_ops
            );
        }
    });
}

#[test]
fn prop_sequencer_storage_errors_propagate() {
    proptest!(|(
        seed in any::<u64>(),
        room_id in any::<u128>(),
    )| {
        // 100% failure rate - all operations fail
        let storage = ChaoticStorage::with_seed(MemoryStorage::new(), 1.0, seed);
        let mut sequencer = Sequencer::new();

        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(1);
        header.set_epoch(0);
        header.set_log_index(0);

        let frame = Frame::new(header, Bytes::new());

        // Process frame - should fail due to storage error
        let result = sequencer.process_frame(frame, &storage);

        // INVARIANT: Storage errors must propagate, not be swallowed
        prop_assert!(result.is_err(), "Storage errors must propagate to caller");
    });
}
