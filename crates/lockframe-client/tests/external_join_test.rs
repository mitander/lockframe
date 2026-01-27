//! External join tests for MLS external commits.
//!
//! This file contains ONLY tests that verify specific behaviors that cannot
//! be easily covered by property-based or DST tests:
//! - Error handling for invalid inputs
//! - Client state machine transitions
//! - Determinism requirements for DST

use lockframe_client::{Client, ClientAction, ClientEvent, ClientIdentity};
use lockframe_core::mls::{MlsGroup, RoomId};
use lockframe_harness::SimEnv;
use lockframe_proto::{FrameHeader, Opcode, Payload, payloads::mls::GroupInfoPayload};
use turmoil::Builder;

const ROOM_ID: RoomId = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

/// WHY THIS TEST IS NEEDED:
/// External join must gracefully handle malformed `GroupInfo`:
/// - Truncated data, invalid TLS encoding, wrong group parameters
/// - Without this test, attackers could crash clients with garbage data
/// - DST won't generate invalid `GroupInfo`, so this needs explicit testing
#[test]
fn external_join_rejects_invalid_group_info() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();

        // Garbage data
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let result = MlsGroup::join_from_external(env.clone(), ROOM_ID, 2, &garbage);
        assert!(result.is_err(), "Should reject garbage GroupInfo");

        // Empty data
        let empty: Vec<u8> = vec![];
        let result = MlsGroup::join_from_external(env.clone(), ROOM_ID, 2, &empty);
        assert!(result.is_err(), "Should reject empty GroupInfo");

        // Truncated valid-looking data
        let truncated = vec![0x00, 0x01, 0x00]; // MLS version prefix, truncated
        let result = MlsGroup::join_from_external(env, ROOM_ID, 2, &truncated);
        assert!(result.is_err(), "Should reject truncated GroupInfo");

        Ok(())
    });

    sim.run().unwrap();
}

/// WHY THIS TEST IS NEEDED:
/// Prevents duplicate membership - a client should not be able to external
/// join a room they're already a member of. This is a state machine invariant
/// that DST might not catch because it typically doesn't try invalid
/// operations.
#[test]
fn client_external_join_existing_room_fails() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();
        let alice = ClientIdentity::new(1);
        let mut alice_client = Client::new(env, alice);

        // Alice creates room
        alice_client.handle(ClientEvent::CreateRoom { room_id: ROOM_ID }).expect("create room");

        // Alice tries to external join same room - should fail
        let result = alice_client.handle(ClientEvent::ExternalJoin { room_id: ROOM_ID });
        assert!(result.is_err(), "Should not allow external join to existing room");

        Ok(())
    });

    sim.run().unwrap();
}

/// WHY THIS TEST IS NEEDED:
/// Verifies the Client correctly initiates external join by:
/// 1. Accepting `ExternalJoin` event for unknown room
/// 2. Generating `GroupInfoRequest` frame
/// 3. Tracking pending join state
///
/// This tests the initiation step only - the full flow is in DST.
#[test]
fn client_external_join_requests_group_info() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();
        let bob = ClientIdentity::new(2);
        let mut bob_client = Client::new(env, bob);

        let actions = bob_client
            .handle(ClientEvent::ExternalJoin { room_id: ROOM_ID })
            .expect("external join should initiate");

        // Should produce exactly one GroupInfoRequest
        let frames: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                ClientAction::Send(f) => Some(f),
                _ => None,
            })
            .collect();

        assert_eq!(frames.len(), 1, "Should send exactly one frame");
        assert_eq!(
            frames[0].header.opcode_enum(),
            Some(Opcode::GroupInfoRequest),
            "Frame should be GroupInfoRequest"
        );

        Ok(())
    });

    sim.run().unwrap();
}

/// WHY THIS TEST IS NEEDED:
/// Verifies `GroupInfo` response handling produces correct outputs:
/// - `ExternalCommit` frame (`Opcode::Commit` with external commit flag)
/// - `RoomJoined` action for the app layer
///
/// This is the critical state transition from "pending join" to "joined".
#[test]
fn client_processes_group_info_response() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();

        // Alice creates room and exports GroupInfo
        let (alice_group, _) = MlsGroup::new(env.clone(), ROOM_ID, 1).expect("alice create");
        let group_info_bytes = alice_group.export_group_info().expect("export");

        // Bob initiates external join
        let bob = ClientIdentity::new(2);
        let mut bob_client = Client::new(env, bob);
        bob_client.handle(ClientEvent::ExternalJoin { room_id: ROOM_ID }).expect("initiate");

        // Simulate server responding with GroupInfo
        let payload = GroupInfoPayload { room_id: ROOM_ID, epoch: 0, group_info_bytes };
        let frame = Payload::GroupInfo(payload)
            .into_frame(FrameHeader::new(Opcode::GroupInfo))
            .expect("create frame");

        let actions = bob_client.handle(ClientEvent::FrameReceived(frame)).expect("process");

        // Verify outputs
        let has_commit = actions.iter().any(|a| {
            matches!(a, ClientAction::Send(f) if f.header.opcode_enum() == Some(Opcode::Commit)
                || f.header.opcode_enum() == Some(Opcode::ExternalCommit))
        });
        let has_joined = actions.iter().any(|a| matches!(a, ClientAction::RoomJoined { .. }));

        assert!(has_commit, "Should emit Commit/ExternalCommit frame");
        assert!(has_joined, "Should emit RoomJoined action");

        Ok(())
    });

    sim.run().unwrap();
}

/// WHY THIS TEST IS NEEDED:
/// DST requires deterministic behavior - same seed must produce same outputs.
/// This test verifies external join is deterministic, which is critical for:
/// - Bug reproduction (same seed = same failure)
/// - Turmoil simulation correctness
///
/// If this test fails, DST results are unreliable.
#[test]
fn external_join_is_deterministic() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        // Run 1 with seed 42
        let env1 = SimEnv::with_seed(42);
        let (alice1, _) = MlsGroup::new(env1.clone(), ROOM_ID, 1).expect("alice1");
        let group_info1 = alice1.export_group_info().expect("export1");
        let (bob1, actions1) =
            MlsGroup::join_from_external(env1, ROOM_ID, 2, &group_info1).expect("bob1");

        // Run 2 with same seed 42
        let env2 = SimEnv::with_seed(42);
        let (alice2, _) = MlsGroup::new(env2.clone(), ROOM_ID, 1).expect("alice2");
        let group_info2 = alice2.export_group_info().expect("export2");
        let (bob2, actions2) =
            MlsGroup::join_from_external(env2, ROOM_ID, 2, &group_info2).expect("bob2");

        // Oracle: Same seed MUST produce identical results
        assert_eq!(bob1.epoch(), bob2.epoch(), "Same seed must produce same epoch");
        assert_eq!(actions1.len(), actions2.len(), "Same seed must produce same action count");

        // Run 3 with different seed - should still work (different internal state)
        let env3 = SimEnv::with_seed(99);
        let (alice3, _) = MlsGroup::new(env3.clone(), ROOM_ID, 1).expect("alice3");
        let group_info3 = alice3.export_group_info().expect("export3");
        let (_bob3, actions3) =
            MlsGroup::join_from_external(env3, ROOM_ID, 2, &group_info3).expect("bob3");

        assert!(!actions3.is_empty(), "Different seed should still produce valid join");

        Ok(())
    });

    sim.run().unwrap();
}

/// WHY THIS TEST IS NEEDED:
/// Verifies `MlsGroup::join_from_external` produces valid MLS state:
/// - Correct `room_id` and `member_id`
/// - Epoch advanced to 1 (external commit advances epoch)
/// - Actions include commit frame
///
/// This tests the MLS layer in isolation before Client integration.
#[test]
fn external_join_creates_valid_commit() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();

        // Alice creates room at epoch 0
        let (alice_group, _) = MlsGroup::new(env.clone(), ROOM_ID, 1).expect("alice create");
        assert_eq!(alice_group.epoch(), 0);

        let group_info_bytes = alice_group.export_group_info().expect("export");

        // Bob joins via external commit
        let (bob_group, actions) =
            MlsGroup::join_from_external(env, ROOM_ID, 2, &group_info_bytes).expect("bob");

        // Verify Bob's group state
        assert_eq!(bob_group.room_id(), ROOM_ID);
        assert_eq!(bob_group.member_id(), 2);
        assert_eq!(bob_group.epoch(), 1, "External commit advances epoch");

        // Verify commit action was produced
        let has_commit = actions.iter().any(|a| {
            matches!(
                a,
                lockframe_core::mls::MlsAction::SendCommit { .. }
                    | lockframe_core::mls::MlsAction::PublishGroupInfo { .. }
            )
        });
        assert!(has_commit, "Should produce commit-related action");

        Ok(())
    });

    sim.run().unwrap();
}
