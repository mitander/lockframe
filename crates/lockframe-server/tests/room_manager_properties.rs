//! Property-based tests for RoomManager
//!
//! These tests verify invariants that must hold for all inputs, using
//! deterministic simulation (SimEnv) for reproducibility.

use std::collections::HashSet;

use bytes::Bytes;
use lockframe_harness::SimEnv;
use lockframe_proto::{Frame, FrameHeader, Opcode};
use lockframe_server::{MemoryStorage, RoomAction, RoomError, RoomManager, Storage};
use proptest::prelude::*;

/// Helper to create a test frame
fn create_test_frame(room_id: u128, sender_id: u64, epoch: u64, payload: Vec<u8>) -> Frame {
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(room_id);
    header.set_sender_id(sender_id);
    header.set_epoch(epoch);
    header.set_log_index(0);
    Frame::new(header, Bytes::from(payload))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: Creating a room always makes has_room() return true
    #[test]
    fn prop_create_room_enables_has_room(
        seed in any::<u64>(),
        room_id in 1u128..,  // Note: 0 is reserved/invalid
        creator in any::<u64>()
    ) {
        let env = SimEnv::with_seed(seed);
        let mut manager = RoomManager::new();

        manager.create_room(room_id, creator, &env)?;
        prop_assert!(manager.has_room(room_id));
    }

    /// Property: Creating same room twice always fails
    #[test]
    fn prop_duplicate_room_always_fails(
        seed in any::<u64>(),
        room_id in 1u128..,
        creator in any::<u64>()
    ) {
        let env = SimEnv::with_seed(seed);
        let mut manager = RoomManager::new();

        manager.create_room(room_id, creator, &env)?;

        let result = manager.create_room(room_id, creator, &env);
        prop_assert!(matches!(result, Err(RoomError::RoomAlreadyExists(_))));
    }

    /// Property: Can create many distinct rooms
    #[test]
    fn prop_many_distinct_rooms(
        seed in any::<u64>(),
        room_ids in prop::collection::vec(1u128.., 1..20)
    ) {
        let env = SimEnv::with_seed(seed);
        let mut manager = RoomManager::new();

        // Deduplicate to create unique ids
        let unique_ids: HashSet<u128> = room_ids.into_iter().collect();

        for room_id in &unique_ids {
            manager.create_room(*room_id, 0, &env)?;
        }

        for room_id in &unique_ids {
            prop_assert!(manager.has_room(*room_id));
        }
    }

    /// Property: Processing frame for unknown room always fails with RoomNotFound
    #[test]
    fn prop_process_frame_rejects_unknown_room(
        seed in any::<u64>(),
        room_id in 1u128..,
        sender_id in 1u64..1000,
        epoch in 0u64..1000000,
        payload in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        let env = SimEnv::with_seed(seed);
        let mut manager = RoomManager::new();
        let storage = MemoryStorage::new();

        // Do NOT create the room, it should be unknown
        let frame = create_test_frame(room_id, sender_id, epoch, payload);
        let result = manager.process_frame(frame, &env, &storage);
        prop_assert!(matches!(result, Err(RoomError::RoomNotFound(_))));
    }

    /// Property: Sync request pagination correctly handles limit and has_more
    #[test]
    fn prop_sync_request_pagination(
        seed in any::<u64>(),
        room_id in 1u128..,
        creator in 1u64..1000,
        total_frames in 10usize..100,
        page_size in 1usize..20,
        start_offset in 0u64..50
    ) {
        let env = SimEnv::with_seed(seed);
        let mut manager = RoomManager::new();
        let storage = MemoryStorage::new();

        manager.create_room(room_id, creator, &env)?;

        for i in 0..total_frames {
            let mut header = FrameHeader::new(Opcode::AppMessage);
            header.set_room_id(room_id);
            header.set_sender_id(creator);
            header.set_log_index(i as u64);
            header.set_epoch(0);
            let frame = Frame::new(header, Bytes::from(format!("msg {i}")));
            storage.store_frame(room_id, i as u64, &frame)?;
        }

        // Request sync with pagination
        let requester = 100;
        let start = start_offset.min(total_frames as u64);
        let result = manager.handle_sync_request(
            room_id,
            requester,
            start,
            page_size,
            &env,
            &storage
        );

        prop_assert!(result.is_ok());

        if let Ok(RoomAction::SendSyncResponse { frames, has_more, .. }) = result {
            let remaining = (total_frames as u64).saturating_sub(start) as usize;
            let expected_len = remaining.min(page_size);
            prop_assert_eq!(frames.len(), expected_len);

            let expected_has_more = remaining > page_size;
            prop_assert_eq!(has_more, expected_has_more);

            for frame_bytes in frames.iter() {
                prop_assert!(!frame_bytes.is_empty());
            }
        } else {
            prop_assert!(false);
        }
    }

    /// Property: Sync request for unknown room always fails
    #[test]
    fn prop_sync_request_unknown_room_fails(
        seed in any::<u64>(),
        room_id in 1u128..,
        requester in 1u64..1000,
        start_index in any::<u64>(),
        limit in 1usize..100
    ) {
        let env = SimEnv::with_seed(seed);
        let manager = RoomManager::new();
        let storage = MemoryStorage::new();

        // Do NOT create the room
        let result = manager.handle_sync_request(
            room_id,
            requester,
            start_index,
            limit,
            &env,
            &storage
        );

        prop_assert!(matches!(result, Err(RoomError::RoomNotFound(_))));
    }

    /// Property: Process frame produces correct action sequence
    #[test]
    fn prop_process_frame_produces_persist_and_broadcast(
        seed in any::<u64>(),
        room_id in 1u128..,
        creator in 1u64..1000,
        epoch in 0u64..1000000,
        payload in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        let env = SimEnv::with_seed(seed);
        let mut manager = RoomManager::new();
        let storage = MemoryStorage::new();

        manager.create_room(room_id, creator, &env)?;

        let frame = create_test_frame(room_id, creator, epoch, payload);

        // Should produce PersistFrame and Broadcast actions
        let result = manager.process_frame(frame, &env, &storage)?;
        prop_assert_eq!(result.len(), 2);

        let is_persist = matches!(&result[0], RoomAction::PersistFrame { .. });
        let is_broadcast = matches!(&result[1], RoomAction::Broadcast { .. });
        prop_assert!(is_persist);
        prop_assert!(is_broadcast);
    }
}
