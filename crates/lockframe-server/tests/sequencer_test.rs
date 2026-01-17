//! Property tests for sequencer crash recovery.
//!
//! Tests verify that a new sequencer can resume from where the previous one
//! left off. Basic sequencing invariants (no gaps, monotonic indices) are
//! tested in chaos_sequencer.rs.

use bytes::Bytes;
use lockframe_proto::{Frame, FrameHeader, Opcode};
use lockframe_server::{MemoryStorage, Sequencer, SequencerAction, Storage};
use proptest::prelude::*;

/// Helper to create a test frame.
fn create_test_frame(room_id: u128, sender_id: u64, epoch: u64, payload: Vec<u8>) -> Frame {
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(room_id);
    header.set_sender_id(sender_id);
    header.set_epoch(epoch);

    Frame::new(header, Bytes::from(payload))
}

/// Execute sequencer actions against storage.
fn execute_actions(actions: Vec<SequencerAction>, storage: &MemoryStorage) {
    for action in actions {
        if let SequencerAction::StoreFrame { room_id, log_index, frame } = action {
            storage.store_frame(room_id, log_index, &frame).expect("store_frame failed");
        }
    }
}

/// Verify sequential log indices with no gaps.
fn verify_sequential_indices(storage: &MemoryStorage, room_id: u128, expected_count: usize) {
    let frames = storage.load_frames(room_id, 0, expected_count + 10).expect("load_frames failed");
    assert_eq!(frames.len(), expected_count);

    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(frame.header.log_index(), i as u64);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Sequencer crash recovery with random crash point.
    ///
    /// Verifies that after a Sequencer "crash" (drop), a new sequencer
    /// correctly resumes sequencing from where the previous one left off.
    /// The crash point is randomized to explore all possible failure scenarios.
    #[test]
    fn prop_sequencer_crash_recovery(
        crash_point in 1u64..50,
        total_frames in 10u64..100,
        room_id in any::<u128>(),
        sender_id in 1u64..1000,
    ) {
        let storage = MemoryStorage::new();
        let crash_point = crash_point.min(total_frames - 1);

        // Sequencer 1: Process frames until crash_point
        {
            let mut sequencer = Sequencer::new();

            for i in 0..crash_point {
                let frame = create_test_frame(room_id, sender_id, 0, vec![i as u8]);
                let actions = sequencer.process_frame(frame, &storage)?;
                execute_actions(actions, &storage);
            }
        } // Sequencer dropped (simulates crash)

        // Sequencer 2: Recover and continue
        {
            let mut sequencer = Sequencer::new();

            for i in crash_point..total_frames {
                let frame = create_test_frame(room_id, sender_id, 0, vec![i as u8]);
                let actions = sequencer.process_frame(frame, &storage)?;
                execute_actions(actions, &storage);
            }
        }

        // ORACLE: Verify no gaps across restart
        verify_sequential_indices(&storage, room_id, total_frames as usize);

        // ORACLE: Verify monotonic log indices
        let frames = storage.load_frames(room_id, 0, (total_frames + 10) as usize)?;
        for window in frames.windows(2) {
            let prev = window[0].header.log_index();
            let next = window[1].header.log_index();
            prop_assert_eq!(next, prev + 1);
        }

        // ORACLE: Verify payloads preserved across crash
        for (i, frame) in frames.iter().enumerate() {
            prop_assert_eq!(frame.payload.as_ref(),&[i as u8]);
        }
    }

    /// Multiple crashes during sequencing.
    ///
    /// Verifies recovery works even with multiple sequential crashes.
    #[test]
    fn prop_sequencer_multiple_crashes(
        crash_points in prop::collection::vec(1u64..20, 2..5),
        room_id in any::<u128>(),
        sender_id in 1u64..1000,
    ) {
        let storage = MemoryStorage::new();
        let mut current_index = 0u64;

        // Process frames in segments, "crashing" between each
        for segment_size in crash_points {
            let mut sequencer = Sequencer::new();

            for _ in 0..segment_size {
                let frame = create_test_frame(room_id, sender_id, 0, vec![current_index as u8]);
                let actions = sequencer.process_frame(frame, &storage)?;
                execute_actions(actions, &storage);
                current_index += 1;
            }
            // Sequencer dropped (simulates crash)
        }

        // ORACLE: Verify no gaps despite multiple crashes
        verify_sequential_indices(&storage, room_id, current_index as usize);
    }
}
