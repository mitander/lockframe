//! Room Manager tests

use bytes::Bytes;
use kalandra_core::{
    room_manager::{RoomError, RoomManager},
    storage::{MemoryStorage, Storage},
};
use kalandra_proto::{Frame, FrameHeader, Opcode};

// Test environment using system RNG (std::time::Instant)
#[derive(Clone)]
struct TestEnv;

impl kalandra_core::env::Environment for TestEnv {
    type Instant = std::time::Instant;

    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, duration: std::time::Duration) -> impl std::future::Future<Output = ()> + Send {
        async move {
            tokio::time::sleep(duration).await;
        }
    }

    fn random_bytes(&self, buffer: &mut [u8]) {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buffer);
    }
}

#[test]
fn room_manager_new_has_no_rooms() {
    let manager = RoomManager::<TestEnv>::new();
    assert!(!manager.has_room(0x1234));
}

#[test]
fn create_room_succeeds_for_new_room() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    let result = manager.create_room(room_id, creator, &env);
    assert!(result.is_ok());
    assert!(manager.has_room(room_id));
}

#[test]
fn create_room_rejects_duplicate() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    // First creation succeeds
    manager.create_room(room_id, creator, &env).unwrap();

    // Second creation fails
    let result = manager.create_room(room_id, creator, &env);
    assert!(matches!(result, Err(RoomError::RoomAlreadyExists(_))));
}

#[test]
fn create_room_stores_metadata() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    manager.create_room(room_id, creator, &env).unwrap();

    // Metadata should be stored (we'll verify this when we add getter methods)
    assert!(manager.has_room(room_id));
}

#[test]
fn create_multiple_rooms() {
    let env = TestEnv;
    let mut manager = RoomManager::new();

    let room1 = 0x1111_1111_1111_1111_1111_1111_1111_1111;
    let room2 = 0x2222_2222_2222_2222_2222_2222_2222_2222;
    let room3 = 0x3333_3333_3333_3333_3333_3333_3333_3333;

    manager.create_room(room1, 1, &env).unwrap();
    manager.create_room(room2, 2, &env).unwrap();
    manager.create_room(room3, 3, &env).unwrap();

    assert!(manager.has_room(room1));
    assert!(manager.has_room(room2));
    assert!(manager.has_room(room3));
}

#[test]
fn process_frame_rejects_unknown_room() {
    let env = TestEnv;
    let mut manager = RoomManager::<TestEnv>::new();
    let storage = MemoryStorage::new();

    // Create a frame for a room that doesn't exist
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(0x9999_9999_9999_9999_9999_9999_9999_9999);
    header.set_sender_id(42);
    header.set_epoch(0);
    let frame = Frame::new(header, Bytes::new());

    let result = manager.process_frame(frame, &env, &storage);
    assert!(matches!(result, Err(RoomError::RoomNotFound(_))));
}

#[test]
fn process_frame_succeeds_for_valid_frame() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let storage = MemoryStorage::new();

    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    // Create the room first
    manager.create_room(room_id, creator, &env).unwrap();

    // Create a valid frame
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(room_id);
    header.set_sender_id(creator);
    header.set_epoch(0);
    let frame = Frame::new(header, Bytes::new());

    let result = manager.process_frame(frame, &env, &storage);
    if let Err(ref e) = result {
        panic!("process_frame failed: {:?}", e);
    }
    assert!(result.is_ok());

    let actions = result.unwrap();
    // Should have actions (AcceptFrame becomes PersistFrame, StoreFrame becomes
    // PersistFrame, BroadcastToRoom becomes Broadcast) Sequencer returns 3
    // actions: AcceptFrame, StoreFrame, BroadcastToRoom
    assert!(!actions.is_empty());
    assert_eq!(actions.len(), 3);
}

#[test]
fn process_frame_returns_correct_action_types() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let storage = MemoryStorage::new();

    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    // Create the room first
    manager.create_room(room_id, creator, &env).unwrap();

    // Create a valid frame
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(room_id);
    header.set_sender_id(creator);
    header.set_epoch(0);
    let frame = Frame::new(header, Bytes::from("test message"));

    let result = manager.process_frame(frame, &env, &storage);
    assert!(result.is_ok());

    let actions = result.unwrap();

    // Verify we have the right action types
    use kalandra_core::room_manager::RoomAction;

    // First two should be PersistFrame (from AcceptFrame and StoreFrame)
    assert!(matches!(actions[0], RoomAction::PersistFrame { .. }));
    assert!(matches!(actions[1], RoomAction::PersistFrame { .. }));

    // Last should be Broadcast (from BroadcastToRoom)
    assert!(matches!(actions[2], RoomAction::Broadcast { .. }));
}

#[test]
fn process_frame_rejects_wrong_epoch() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let storage = MemoryStorage::new();

    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    // Create room (epoch 0)
    manager.create_room(room_id, creator, &env).unwrap();

    // Store initial MLS state at epoch 0
    use kalandra_core::mls::MlsGroupState;
    let mls_state = MlsGroupState::new(room_id, 0, [0u8; 32], vec![creator], vec![]);
    storage.store_mls_state(room_id, &mls_state).unwrap();

    // Create frame with wrong epoch (epoch 5, but room is at epoch 0)
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_room_id(room_id);
    header.set_sender_id(creator);
    header.set_epoch(5); // Wrong epoch!
    let frame = Frame::new(header, Bytes::new());

    let result = manager.process_frame(frame, &env, &storage);
    assert!(matches!(result, Err(RoomError::MlsValidation(_))));
}
