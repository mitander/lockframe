//! Server storage tests for external join flow.

use lockframe_client::{Client, ClientAction, ClientEvent, ClientIdentity};
use lockframe_core::mls::RoomId;
use lockframe_harness::{SimEnv, SimServer};
use lockframe_proto::{Frame, Opcode};
use lockframe_server::{ServerEvent, Storage};
use turmoil::Builder;

const ROOM_ID: RoomId = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

fn extract_frames_by_opcode(actions: &[ClientAction], opcode: Opcode) -> Vec<Frame> {
    actions
        .iter()
        .filter_map(|a| match a {
            ClientAction::Send(f) if f.header.opcode_enum() == Some(opcode) => Some(f.clone()),
            _ => None,
        })
        .collect()
}

/// WHY THIS TEST IS NEEDED:
/// Verifies server correctly stores and retrieves GroupInfo for external
/// joiners. This is server-specific behavior that client tests cannot verify:
/// - Storage trait implementation works correctly
/// - GroupInfo bytes survive storage round-trip
/// - Epoch is correctly stored
///
/// Without this test, GroupInfo could be corrupted in storage and external
/// joins would fail with no indication of where the bug is.
#[test]
fn server_stores_and_retrieves_group_info() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Create connection for Alice
        let _ =
            server.driver_mut().process_event(ServerEvent::ConnectionAccepted { session_id: 1 });

        // Alice creates room
        let env = SimEnv::new();
        let alice_id = ClientIdentity::new(1);
        let mut alice = Client::new(env.clone(), alice_id);

        let create_actions =
            alice.handle(ClientEvent::CreateRoom { room_id: ROOM_ID }).expect("alice create room");

        // Get the GroupInfo frame
        let group_info_frames = extract_frames_by_opcode(&create_actions, Opcode::GroupInfo);
        assert_eq!(group_info_frames.len(), 1, "Should publish GroupInfo on creation");

        // Server processes the GroupInfo frame
        let result = server.process_frame(1, group_info_frames[0].clone()).await;
        assert!(result.is_ok(), "Server should accept GroupInfo: {:?}", result);

        // Verify GroupInfo is stored correctly
        let stored =
            server.driver().storage().load_group_info(ROOM_ID).expect("load should not fail");
        assert!(stored.is_some(), "GroupInfo should be stored");

        let (epoch, stored_bytes) = stored.unwrap();
        assert_eq!(epoch, 0, "Initial epoch should be 0");
        assert!(!stored_bytes.is_empty(), "GroupInfo bytes should not be empty");

        // Verify the stored bytes can be used for external join
        // (This is the critical invariant - storage must not corrupt the data)
        let join_result = lockframe_core::mls::MlsGroup::join_from_external(
            env.clone(),
            ROOM_ID,
            2,
            &stored_bytes,
        );
        assert!(
            join_result.is_ok(),
            "Stored GroupInfo must be usable for external join: {:?}",
            join_result.err()
        );

        Ok(())
    });

    sim.run().unwrap();
}
