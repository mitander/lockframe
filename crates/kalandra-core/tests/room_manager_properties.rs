//! Property-based tests for RoomManager

use std::time::Duration;

use kalandra_core::{
    env::Environment,
    room_manager::{RoomError, RoomManager},
};
use proptest::prelude::*;

#[derive(Clone)]
struct TestEnv;

impl Environment for TestEnv {
    type Instant = std::time::Instant;

    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send {
        async move { tokio::time::sleep(duration).await }
    }

    fn random_bytes(&self, buffer: &mut [u8]) {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buffer);
    }
}

/// Property: Creating a room always makes has_room() return true
#[test]
fn prop_create_room_enables_has_room() {
    proptest!(|(room_id in any::<u128>(), creator in any::<u64>())| {
        let env = TestEnv;
        let mut manager = RoomManager::new();

        manager.create_room(room_id, creator, &env)?;

        prop_assert!(manager.has_room(room_id));
    });
}

/// Property: Creating same room twice always fails
#[test]
fn prop_duplicate_room_always_fails() {
    proptest!(|(room_id in any::<u128>(), creator in any::<u64>())| {
        let env = TestEnv;
        let mut manager = RoomManager::new();

        manager.create_room(room_id, creator, &env)?;
        let result = manager.create_room(room_id, creator, &env);

        prop_assert!(matches!(result, Err(RoomError::RoomAlreadyExists(_))));
    });
}

/// Property: Can create many distinct rooms
#[test]
fn prop_many_distinct_rooms() {
    proptest!(|(room_ids in prop::collection::vec(any::<u128>(), 1..20))| {
        let env = TestEnv;
        let mut manager = RoomManager::new();

        // Create unique room IDs (deduplicate)
        use std::collections::HashSet;
        let unique_ids: HashSet<u128> = room_ids.into_iter().collect();

        for room_id in &unique_ids {
            manager.create_room(*room_id, 0, &env)?;
        }

        // All rooms should exist
        for room_id in &unique_ids {
            prop_assert!(manager.has_room(*room_id));
        }

        // Room count should match
        // (We can't verify this yet without a public room_count() method)
    });
}
