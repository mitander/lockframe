//! Room Manager behavior tests
//!
//! Tests for specific routing behaviors of the server RoomManager.

use std::time::Duration;

use bytes::Bytes;
use lockframe_core::env::Environment;
use lockframe_proto::{Frame, FrameHeader, Opcode};
use lockframe_server::{MemoryStorage, RoomManager};

// Test environment using system RNG
#[derive(Clone)]
struct TestEnv;

impl Environment for TestEnv {
    type Instant = std::time::Instant;

    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send {
        async move {
            tokio::time::sleep(duration).await;
        }
    }

    fn random_bytes(&self, buffer: &mut [u8]) {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buffer);
    }
}

/// Test that the server routes frames without MLS validation.
/// Server is routing-only, clients own the MLS state.
#[test]
fn process_frame_routes_any_epoch() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let storage = MemoryStorage::new();

    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    manager.create_room(room_id, creator, &env).unwrap();

    // Server is routing-only, should accept any epoch
    for epoch in [0, 1, 5, 100] {
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(creator);
        header.set_epoch(epoch);
        let frame = Frame::new(header, Bytes::from(format!("msg at epoch {epoch}")));

        let result = manager.process_frame(frame, &env, &storage);
        assert!(result.is_ok());
    }
}

/// Test that server routes Commit frames like any other frame.
/// Server doesn't process MLS commits, it just routes them.
#[test]
fn process_commit_routes_without_mls_validation() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let storage = MemoryStorage::new();

    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    manager.create_room(room_id, creator, &env).unwrap();

    let mut header = FrameHeader::new(Opcode::Commit);
    header.set_room_id(room_id);
    header.set_sender_id(creator);
    header.set_epoch(0);
    let frame = Frame::new(header, Bytes::from("commit payload"));

    let result = manager.process_frame(frame, &env, &storage);
    assert!(result.is_ok());

    let actions = result.unwrap();
    assert!(!actions.is_empty());
}

/// Test that server routes Welcome frames to recipients.
#[test]
fn process_welcome_routes_without_mls_validation() {
    let env = TestEnv;
    let mut manager = RoomManager::new();
    let storage = MemoryStorage::new();

    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;
    let creator = 42;

    manager.create_room(room_id, creator, &env).unwrap();

    let mut header = FrameHeader::new(Opcode::Welcome);
    header.set_room_id(room_id);
    header.set_sender_id(creator);
    header.set_epoch(0);
    let frame = Frame::new(header, Bytes::from("welcome payload"));

    let result = manager.process_frame(frame, &env, &storage);
    assert!(result.is_ok());
}
