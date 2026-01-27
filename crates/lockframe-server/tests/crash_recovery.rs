//! Crash recovery tests for `RedbStorage`.
//!
//! These tests verify that data persists across database close/reopen cycles,
//! simulating server restarts.

use bytes::Bytes;
use lockframe_core::mls::MlsGroupState;
use lockframe_proto::{Frame, FrameHeader, Opcode};
use lockframe_server::storage::{RedbStorage, Storage};
use tempfile::tempdir;

fn create_test_frame(room_id: u128, log_index: u64, payload: &[u8]) -> Frame {
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(room_id);
    header.set_sender_id(1);
    header.set_epoch(0);
    header.set_log_index(log_index);
    Frame::new(header, Bytes::copy_from_slice(payload))
}

#[test]
fn test_frames_survive_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

    let room_id = 100u128;
    let frame_count = 10;

    // Write frames, then simulate clean shutdown
    {
        let storage = RedbStorage::open(&db_path).unwrap();

        for i in 0..frame_count {
            let frame = create_test_frame(room_id, i, &[i as u8; 32]);
            storage.store_frame(room_id, i, &frame).unwrap();
        }

        // Database dropped
    }

    // Reopen and verify all frames exist
    {
        let storage = RedbStorage::open(&db_path).unwrap();

        let latest = storage.latest_log_index(room_id).unwrap();
        assert_eq!(latest, Some(frame_count - 1));

        let frames = storage.load_frames(room_id, 0, frame_count as usize + 10).unwrap();
        assert_eq!(frames.len(), frame_count as usize);

        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header.log_index(), i as u64);
            assert_eq!(frame.payload.len(), 32);
            assert_eq!(frame.payload[0], i as u8);
        }
    }
}

#[test]
fn test_mls_state_survives_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

    let room_id = 100u128;
    let epoch = 42;
    let tree_hash = [0xAB; 32];
    let members = vec![1, 2, 3, 4, 5];

    // Store MLS state
    {
        let storage = RedbStorage::open(&db_path).unwrap();
        let state = MlsGroupState::new(room_id, epoch, tree_hash, members.clone());
        storage.store_mls_state(room_id, &state).unwrap();
    }

    // Reopen and verify
    {
        let storage = RedbStorage::open(&db_path).unwrap();
        let loaded = storage.load_mls_state(room_id).unwrap().unwrap();
        assert_eq!(loaded.room_id, room_id);
        assert_eq!(loaded.epoch, epoch);
        assert_eq!(loaded.tree_hash, tree_hash);
        assert_eq!(loaded.members, members);
    }
}

#[test]
fn test_group_info_survives_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

    let room_id = 100u128;
    let epoch = 7u64;
    let group_info = b"group info payload for external joiners";

    // Store group info
    {
        let storage = RedbStorage::open(&db_path).unwrap();
        storage.store_group_info(room_id, epoch, group_info).unwrap();
    }

    // Reopen and verify
    {
        let storage = RedbStorage::open(&db_path).unwrap();
        let (loaded_epoch, loaded_bytes) = storage.load_group_info(room_id).unwrap().unwrap();
        assert_eq!(loaded_epoch, epoch);
        assert_eq!(loaded_bytes, group_info);
    }
}

#[test]
fn test_multiple_rooms_survive_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

    let room_count = 5;
    let frames_per_room = 10;

    // Create multiple rooms with frames
    {
        let storage = RedbStorage::open(&db_path).unwrap();

        for room_idx in 0..room_count {
            let room_id = room_idx as u128;

            for frame_idx in 0..frames_per_room {
                let frame = create_test_frame(room_id, frame_idx, &[room_idx as u8; 16]);
                storage.store_frame(room_id, frame_idx, &frame).unwrap();
            }

            let state = MlsGroupState::new(
                room_id,
                room_idx as u64, // epoch = room index
                [room_idx as u8; 32],
                vec![room_idx as u64],
            );
            storage.store_mls_state(room_id, &state).unwrap();
        }
    }

    // Reopen and verify each room independently
    {
        let storage = RedbStorage::open(&db_path).unwrap();

        for room_idx in 0..room_count {
            let room_id = room_idx as u128;

            let frames = storage.load_frames(room_id, 0, 100).unwrap();
            assert_eq!(frames.len(), frames_per_room as usize, "room {room_idx} frame count");

            let state = storage.load_mls_state(room_id).unwrap().unwrap();
            assert_eq!(state.epoch, room_idx as u64);

            let latest = storage.latest_log_index(room_id).unwrap();
            assert_eq!(latest, Some(frames_per_room - 1));
        }
    }
}

#[test]
fn test_continue_after_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

    let room_id = 100u128;

    // Write initial frames
    {
        let storage = RedbStorage::open(&db_path).unwrap();

        for i in 0..5 {
            let frame = create_test_frame(room_id, i, b"phase1");
            storage.store_frame(room_id, i, &frame).unwrap();
        }
    }

    // Reopen and continue writing where we left off
    {
        let storage = RedbStorage::open(&db_path).unwrap();

        let latest = storage.latest_log_index(room_id).unwrap();
        assert_eq!(latest, Some(4));

        for i in 5..10 {
            let frame = create_test_frame(room_id, i, b"phase2");
            storage.store_frame(room_id, i, &frame).unwrap();
        }
    }

    // Verify complete sequence
    {
        let storage = RedbStorage::open(&db_path).unwrap();

        let frames = storage.load_frames(room_id, 0, 100).unwrap();
        assert_eq!(frames.len(), 10);

        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header.log_index(), i as u64);

            let expected_payload = if i < 5 { b"phase1".as_slice() } else { b"phase2".as_slice() };
            assert_eq!(frame.payload.as_ref(), expected_payload);
        }
    }
}
