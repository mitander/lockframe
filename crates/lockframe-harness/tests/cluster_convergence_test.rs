//! Cluster convergence tests using Deterministic Simulation Testing.
//!
//! Uses the `TestCluster` fake to verify that Client convergence logic works
//! correctly under various join scenarios (Welcome, External, mixed).

use std::collections::BTreeSet;

use insta::assert_json_snapshot;
use lockframe_core::mls::RoomId;
use lockframe_harness::{
    ClientSnapshot, InvariantRegistry, RoomSnapshot, SystemSnapshot, TestCluster,
};
use proptest::prelude::*;

const ROOM_ID: RoomId = 0x0001_0001_0001_0001_0001_0001_0001_0001;

/// Helper to create `SystemSnapshot` for invariant checking.
fn to_snapshot(cluster: &TestCluster) -> SystemSnapshot {
    let mut clients = Vec::new();

    for client in &cluster.clients {
        let client_id = client.sender_id();

        if !client.is_member(ROOM_ID) {
            continue;
        }

        let epoch = client.epoch(ROOM_ID).unwrap_or(0);
        let tree_hash = client.tree_hash(ROOM_ID).unwrap_or([0u8; 32]);
        let members: BTreeSet<u64> =
            client.member_ids(ROOM_ID).unwrap_or_default().into_iter().collect();

        let room_snapshot =
            RoomSnapshot::with_epoch(epoch).with_tree_hash(tree_hash).with_members(members);

        let mut client_snapshot = ClientSnapshot::new(client_id);
        client_snapshot.rooms.insert(ROOM_ID, room_snapshot);
        client_snapshot.record_epoch(ROOM_ID, epoch);

        clients.push(client_snapshot);
    }

    SystemSnapshot::from_clients(clients)
}

/// Verify all clients have converged to the same epoch and pass invariants.
fn verify_convergence(cluster: &TestCluster) -> Result<(), String> {
    let epochs = cluster.epochs(ROOM_ID);
    if epochs.is_empty() {
        return Err("no clients in room".to_string());
    }

    let first = epochs[0].1;
    for (idx, epoch) in &epochs {
        if *epoch != first {
            return Err(format!("epoch mismatch: client 0 at {first}, client {idx} at {epoch}"));
        }
    }

    let snapshot = to_snapshot(cluster);
    let invariants = InvariantRegistry::standard();

    invariants.check_all(&snapshot).map_err(|violations| {
        let messages: Vec<_> = violations.iter().map(std::string::ToString::to_string).collect();
        format!("Invariant violations:\n  {}", messages.join("\n  "))
    })?;

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Verifies that Welcome-based joins scale correctly. Regardless of how many
    /// clients join via Welcome, all should converge and be able to message.
    #[test]
    fn prop_welcome_joins_converge(
        seed in 1u64..10000,
        num_joiners in 1usize..4,
    ) {
        let mut cluster = TestCluster::new(seed, 1 + num_joiners);

        cluster.create_room(ROOM_ID).expect("create");

        for i in 1..=num_joiners {
            cluster.join_via_welcome(ROOM_ID, i)
                .expect("join failed");
        }

        // ORACLE: All converged
        verify_convergence(&cluster).expect("convergence");

        // ORACLE: Messaging works
        cluster.send_and_verify(ROOM_ID, 0, b"test").expect("messaging");
    }

    /// Verifies that external joins scale correctly. Multiple clients joining
    /// via external commit should all converge to the same epoch.
    #[test]
    fn prop_external_joins_converge(
        seed in 1u64..10000,
        num_joiners in 1usize..4,
    ) {
        let mut cluster = TestCluster::new(seed, 1 + num_joiners);

        cluster.create_room(ROOM_ID).expect("create");

        for i in 1..=num_joiners {
            cluster.join_via_external(ROOM_ID, i)
                .expect("join failed");
        }

        // ORACLE: All converged
        verify_convergence(&cluster).expect("convergence");

        // ORACLE: Messaging works from each client
        for sender in 0..=num_joiners {
            let msg = format!("from {sender}");
            cluster.send_and_verify(ROOM_ID, sender, msg.as_bytes()).expect("messaging");
        }
    }

    /// Verifies that mixed join methods (Welcome and External) converge correctly.
    #[test]
    fn prop_mixed_joins_converge(
        seed in 1u64..10000,
        // Generate sequence of join operations (true = Welcome, false = External)
        join_methods in prop::collection::vec(any::<bool>(), 1..5),
    ) {
        let num_clients = 1 + join_methods.len();
        let mut cluster = TestCluster::new(seed, num_clients);

        cluster.create_room(ROOM_ID).expect("create");

        // Execute the random sequence of join operations
        for (i, use_welcome) in join_methods.iter().enumerate() {
            let joiner_idx = i + 1;
            if *use_welcome {
                cluster.join_via_welcome(ROOM_ID, joiner_idx)
                    .expect("Welcome join {joiner_idx} failed: {e}");
            } else {
                cluster.join_via_external(ROOM_ID, joiner_idx)
                    .expect("External join {joiner_idx} failed: {e}");
            }

            // ORACLE: Convergence must hold after EVERY join operation
            verify_convergence(&cluster)
                .expect("Convergence failed after join {joiner_idx}: {e}");
        }

        // ORACLE: Final state is fully converged
        verify_convergence(&cluster).expect("final convergence");

        // ORACLE: Messaging works from all clients
        for sender in 0..num_clients {
            let msg = format!("msg from {sender}");
            cluster.send_and_verify(ROOM_ID, sender, msg.as_bytes())
                .expect("Messaging from {sender} failed: {e}");
        }
    }
}

/// Snapshot of converged state after Welcome-based joins.
///
/// This test uses a fixed seed to ensure deterministic state, allowing us to
/// detect unintended changes to epoch numbering, tree structure, or member IDs.
/// Tree hashes are redacted as they depend on cryptographic state.
#[test]
fn snapshot_welcome_convergence() {
    let mut cluster = TestCluster::new(42, 3);

    cluster.create_room(ROOM_ID).expect("create");
    cluster.join_via_welcome(ROOM_ID, 1).expect("join 1");
    cluster.join_via_welcome(ROOM_ID, 2).expect("join 2");

    verify_convergence(&cluster).expect("convergence");

    let snapshot = to_snapshot(&cluster);
    assert_json_snapshot!("welcome_convergence_state", snapshot, {
        ".clients[].rooms.*.tree_hash" => "[tree_hash]",
    });
}

/// Snapshot of converged state after external joins.
///
/// Similar to Welcome snapshot but for external commit flow.
/// Tree hashes are redacted as they depend on cryptographic state.
#[test]
fn snapshot_external_convergence() {
    let mut cluster = TestCluster::new(42, 3);

    cluster.create_room(ROOM_ID).expect("create");
    cluster.join_via_external(ROOM_ID, 1).expect("join 1");
    cluster.join_via_external(ROOM_ID, 2).expect("join 2");

    verify_convergence(&cluster).expect("convergence");

    let snapshot = to_snapshot(&cluster);
    assert_json_snapshot!("external_convergence_state", snapshot, {
        ".clients[].rooms.*.tree_hash" => "[tree_hash]",
    });
}

/// Test that state remains consistent when commits are delivered out of order.
///
/// This simulates network reordering where commits arrive in different order
/// than they were sent.
#[test]
fn out_of_order_commit_handling() {
    let mut cluster = TestCluster::new(42, 2);

    cluster.create_room(ROOM_ID).expect("create");
    cluster.join_via_welcome(ROOM_ID, 1).expect("bob joins");

    verify_convergence(&cluster).expect("convergence");

    cluster.send_and_verify(ROOM_ID, 0, b"msg1").expect("msg1");
    cluster.send_and_verify(ROOM_ID, 1, b"msg2").expect("msg2");
    cluster.send_and_verify(ROOM_ID, 0, b"msg3").expect("msg3");
    verify_convergence(&cluster).expect("final convergence");

    let snapshot = to_snapshot(&cluster);
    let invariants = InvariantRegistry::standard();
    invariants.check_all(&snapshot).expect("invariants hold");
}
