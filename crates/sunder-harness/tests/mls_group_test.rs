//! MLS group creation tests.
//!
//! These tests verify basic MLS group functionality using the scenario
//! framework.

use sunder_core::{
    env::Environment,
    mls::{MlsAction, MlsGroup},
};
use sunder_harness::sim_env::SimEnv;
use turmoil::Builder;

#[test]
fn mls_group_creation() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();
        let now = env.now();
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;
        let member_id = 1;

        // Create a new MLS group
        let (group, actions) =
            MlsGroup::new(env, room_id, member_id, now).expect("group creation should succeed");

        // Verify initial state
        assert_eq!(group.room_id(), room_id, "Room ID should match");
        assert_eq!(group.member_id(), member_id, "Member ID should match");
        assert_eq!(group.epoch(), 0, "Initial epoch should be 0");
        assert!(!group.has_pending_commit(), "No pending commit initially");

        // Verify actions
        assert_eq!(actions.len(), 1, "Should have one action (log)");
        match &actions[0] {
            MlsAction::Log { message } => {
                assert!(message.contains("Created group"), "Should log group creation");
                assert!(message.contains("epoch 0"), "Should mention epoch 0");
            },
            _ => panic!("Expected Log action, got {:?}", actions[0]),
        }

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn mls_group_multiple_instances() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        // Verify we can create multiple independent groups
        let env = SimEnv::new();
        let now = env.now();

        let (group1, _) = MlsGroup::new(env.clone(), 1, 100, now).unwrap();
        let (group2, _) = MlsGroup::new(env.clone(), 2, 200, now).unwrap();
        let (group3, _) = MlsGroup::new(env, 3, 300, now).unwrap();

        // Each should have correct room/member IDs
        assert_eq!(group1.room_id(), 1);
        assert_eq!(group1.member_id(), 100);

        assert_eq!(group2.room_id(), 2);
        assert_eq!(group2.member_id(), 200);

        assert_eq!(group3.room_id(), 3);
        assert_eq!(group3.member_id(), 300);

        // All should start at epoch 0
        assert_eq!(group1.epoch(), 0);
        assert_eq!(group2.epoch(), 0);
        assert_eq!(group3.epoch(), 0);

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn mls_group_commit_timeout() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        // Verify commit timeout detection works
        let env = SimEnv::new();
        let now = env.now();
        let (group, _) = MlsGroup::new(env, 1, 100, now).unwrap();

        // No timeout initially
        let timeout_duration = std::time::Duration::from_secs(30);
        assert!(!group.is_commit_timeout(now, timeout_duration));

        // Still no timeout after 29 seconds
        let future = now + std::time::Duration::from_secs(29);
        assert!(!group.is_commit_timeout(future, timeout_duration));

        Ok(())
    });

    sim.run().unwrap();
}
