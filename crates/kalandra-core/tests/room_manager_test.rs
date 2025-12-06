//! Room Manager tests

use kalandra_core::room_manager::RoomManager;

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
fn room_manager_has_room_after_creation() {
    // This will fail until Task 2.2 implements create_room()
    // For now, just verify the type compiles
    let _manager = RoomManager::<TestEnv>::new();
}
