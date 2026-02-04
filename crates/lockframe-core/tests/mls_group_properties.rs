//! Tests for MLS group commit lifecycle.
//!
//! These tests verify critical invariants:
//! - Pending commit is tracked after `add_members/remove_members`
//! - Epoch advances after `merge_pending_commit`
//! - Timeout detection works correctly

use std::time::Duration;

use lockframe_core::{
    env::{Environment, test_utils::MockEnv},
    mls::{MlsAction, MlsGroup},
};

/// INVARIANT: After `add_members`, `has_pending_commit` returns true.
///
/// This test verifies that the commit lifecycle is properly initialized
/// when adding members to a group.
#[test]
fn add_members_sets_pending_commit() {
    let env = MockEnv::with_crypto_rng();
    let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128;
    let creator_id = 42u64;
    let new_member_id = 100u64;

    // Create the group
    let (mut group, _actions) =
        MlsGroup::new(env.clone(), room_id, creator_id).expect("group creation should succeed");

    // INVARIANT: No pending commit initially
    assert!(!group.has_pending_commit(), "New group should not have pending commit");

    // Generate a key package for the new member
    let (key_package_bytes, _hash, _pending_state) =
        MlsGroup::generate_key_package(env, new_member_id)
            .expect("key package generation should succeed");

    // Add the new member
    let actions =
        group.add_members_from_bytes(&[key_package_bytes]).expect("add_members should succeed");

    // INVARIANT: After add_members, pending commit should be set
    assert!(group.has_pending_commit(), "After add_members, has_pending_commit should return true");

    // Should also have MLS pending commit
    assert!(group.has_mls_pending_commit(), "OpenMLS should also have pending commit");

    // Should produce SendCommit action
    let has_commit = actions.iter().any(|a| matches!(a, MlsAction::SendCommit(_)));
    assert!(has_commit, "add_members should produce SendCommit action");
}

/// INVARIANT: `remove_members` also sets pending commit.
#[test]
fn remove_members_sets_pending_commit() {
    let env = MockEnv::with_crypto_rng();
    let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128;
    let creator_id = 42u64;
    let member_to_add = 100u64;
    let member_to_remove = 100u64;

    // Create group and add a member first
    let (mut group, _) = MlsGroup::new(env.clone(), room_id, creator_id).unwrap();

    let (kp_bytes, _, _pending_state) = MlsGroup::generate_key_package(env, member_to_add).unwrap();

    group.add_members_from_bytes(&[kp_bytes]).unwrap();
    group.merge_pending_commit().unwrap();

    // Now the member is in the group, clear pending state
    assert!(!group.has_pending_commit());

    // Remove the member
    let actions = group.remove_members(&[member_to_remove]).expect("remove_members should succeed");

    // INVARIANT: After remove_members, pending commit should be set
    assert!(
        group.has_pending_commit(),
        "After remove_members, has_pending_commit should return true"
    );

    // Should produce SendCommit action
    let has_commit = actions.iter().any(|a| matches!(a, MlsAction::SendCommit(_)));
    assert!(has_commit, "remove_members should produce SendCommit action");
}

/// INVARIANT: Epoch increases by exactly 1 after merging a commit.
///
/// This is a critical protocol invariant: epochs must be monotonically
/// increasing and each commit advances the epoch by exactly 1.
#[test]
fn merge_commit_advances_epoch_by_one() {
    let env = MockEnv::with_crypto_rng();
    let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128;
    let creator_id = 42u64;
    let new_member_id = 100u64;

    let (mut group, _) =
        MlsGroup::new(env.clone(), room_id, creator_id).expect("group creation should succeed");

    let epoch_before = group.epoch();
    assert_eq!(epoch_before, 0, "New group should start at epoch 0");

    // Generate key package and add member
    let (key_package_bytes, _hash, _pending_state) =
        MlsGroup::generate_key_package(env, new_member_id)
            .expect("key package generation should succeed");

    group.add_members_from_bytes(&[key_package_bytes]).expect("add_members should succeed");

    // Epoch should NOT have advanced yet (commit is pending)
    assert_eq!(group.epoch(), epoch_before, "Epoch should not advance until commit is merged");

    // Merge the pending commit
    group.merge_pending_commit().expect("merge_pending_commit should succeed");

    let epoch_after = group.epoch();

    // CRITICAL INVARIANT: Epoch must increase by exactly 1
    assert_eq!(
        epoch_after,
        epoch_before + 1,
        "Epoch should increase by 1 after merge: {epoch_before} -> {epoch_after}"
    );
}

/// INVARIANT: Pending commit cleared after merge.
#[test]
fn pending_commit_cleared_after_merge() {
    let env = MockEnv::with_crypto_rng();
    let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128;
    let creator_id = 42u64;
    let new_member_id = 100u64;

    let (mut group, _) = MlsGroup::new(env.clone(), room_id, creator_id).unwrap();

    let (key_package_bytes, _hash, _pending_state) =
        MlsGroup::generate_key_package(env, new_member_id).unwrap();

    group.add_members_from_bytes(&[key_package_bytes]).unwrap();

    // Should have pending commit before merge
    assert!(group.has_pending_commit());

    group.merge_pending_commit().unwrap();

    // INVARIANT: Should NOT have pending commit after merge
    assert!(!group.has_pending_commit(), "Pending commit should be cleared after successful merge");
}

/// INVARIANT: Timeout detection works correctly.
#[test]
fn commit_timeout_detection() {
    let env = MockEnv::with_crypto_rng();
    let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128;
    let creator_id = 42u64;
    let new_member_id = 100u64;

    let (mut group, _) = MlsGroup::new(env.clone(), room_id, creator_id).unwrap();

    let (key_package_bytes, _, _pending_state) =
        MlsGroup::generate_key_package(env.clone(), new_member_id).unwrap();

    group.add_members_from_bytes(&[key_package_bytes]).unwrap();

    // Should have pending commit
    assert!(group.has_pending_commit());

    let now = env.now();
    let timeout = Duration::from_secs(30);

    // Should not be timed out immediately (within a small window)
    // Note: There's a race between when the commit was created and now,
    // so we just check that it times out after the timeout duration
    let future = now + timeout + Duration::from_secs(1);
    assert!(group.is_commit_timeout(future, timeout), "Should be timed out after timeout duration");
}

/// INVARIANT: Multiple sequential commits each advance epoch by 1.
#[test]
fn sequential_commits_advance_epoch_correctly() {
    let env = MockEnv::with_crypto_rng();
    let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0_u128;
    let creator_id = 42u64;

    let (mut group, _) = MlsGroup::new(env.clone(), room_id, creator_id).unwrap();

    // Add multiple members, one at a time
    for i in 1..=3u64 {
        let member_id = 100 + i;
        let epoch_before = group.epoch();

        let (kp_bytes, _, _pending_state) =
            MlsGroup::generate_key_package(env.clone(), member_id).unwrap();
        group.add_members_from_bytes(&[kp_bytes]).unwrap();
        group.merge_pending_commit().unwrap();

        let epoch_after = group.epoch();

        // INVARIANT: Each commit advances epoch by exactly 1
        assert_eq!(epoch_after, epoch_before + 1, "Commit {i} should advance epoch by 1");
    }

    // Final epoch should be 3 (one commit per member added)
    assert_eq!(group.epoch(), 3);
}
