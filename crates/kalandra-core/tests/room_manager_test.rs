//! Room Manager tests

use kalandra_core::room_manager::{RoomError, RoomManager};

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
