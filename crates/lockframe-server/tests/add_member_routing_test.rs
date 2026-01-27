//! Integration test for /add member flow.
//!
//! This test verifies the EXACT same code paths as the real QUIC server:
//! 1. Connections are registered with `ServerDriver`
//! 2. Hello frames establish `user_id` → `session_id` mapping
//! 3. `KeyPackage` publish/fetch works via registry
//! 4. Welcome frames are routed to correct recipients

use lockframe_proto::{Frame, FrameHeader, Opcode, Payload, payloads::session::Hello};
use lockframe_server::{
    DriverConfig, MemoryStorage, ServerAction, ServerDriver, ServerEvent, SystemEnv,
};

/// Collect all `SendToSession` actions for a specific session.
fn frames_for_session(actions: &[ServerAction], target_session: u64) -> Vec<Frame> {
    actions
        .iter()
        .filter_map(|a| match a {
            ServerAction::SendToSession { session_id, frame } if *session_id == target_session => {
                Some(frame.clone())
            },
            _ => None,
        })
        .collect()
}

/// Check if any Log action contains a specific message substring.
fn has_log_containing(actions: &[ServerAction], substring: &str) -> bool {
    actions.iter().any(|a| match a {
        ServerAction::Log { message, .. } => message.contains(substring),
        _ => false,
    })
}

#[test]
fn test_add_member_welcome_routing() {
    // Create server with fresh state
    let env = SystemEnv::new();
    let storage = MemoryStorage::new();
    let mut server = ServerDriver::new(env, storage, DriverConfig::default());

    // Session IDs (like QUIC server generates)
    let session_1 = 1001; // Alice
    let session_2 = 1002; // Bob

    // User IDs (client-chosen sender_id in Hello)
    let alice_user_id = 42;
    let bob_user_id = 99;

    // Step 1: Both clients connect
    server.process_event(ServerEvent::ConnectionAccepted { session_id: session_1 }).unwrap();
    server.process_event(ServerEvent::ConnectionAccepted { session_id: session_2 }).unwrap();

    // Step 2: Both clients send Hello with their user_id
    // This establishes user_id → session_id mapping in registry

    let alice_hello = Payload::Hello(Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(alice_user_id),
        auth_token: None,
    })
    .into_frame(FrameHeader::new(Opcode::Hello))
    .unwrap();

    let alice_hello_actions = server
        .process_event(ServerEvent::FrameReceived { session_id: session_1, frame: alice_hello })
        .unwrap();

    // Should get HelloReply for Alice
    let alice_replies = frames_for_session(&alice_hello_actions, session_1);
    assert_eq!(alice_replies.len(), 1, "Alice should receive HelloReply");
    assert_eq!(alice_replies[0].header.opcode_enum(), Some(Opcode::HelloReply));

    let bob_hello = Payload::Hello(Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(bob_user_id),
        auth_token: None,
    })
    .into_frame(FrameHeader::new(Opcode::Hello))
    .unwrap();

    let bob_hello_actions = server
        .process_event(ServerEvent::FrameReceived { session_id: session_2, frame: bob_hello })
        .unwrap();

    // Should get HelloReply for Bob
    let bob_replies = frames_for_session(&bob_hello_actions, session_2);
    assert_eq!(bob_replies.len(), 1, "Bob should receive HelloReply");
    assert_eq!(bob_replies[0].header.opcode_enum(), Some(Opcode::HelloReply));

    // Step 3: Bob publishes KeyPackage
    let kp_publish =
        Payload::KeyPackagePublish(lockframe_proto::payloads::mls::KeyPackagePublishRequest {
            key_package_bytes: vec![1, 2, 3, 4], // Fake KeyPackage
            hash_ref: vec![5, 6, 7, 8],
        })
        .into_frame(FrameHeader::new(Opcode::KeyPackagePublish))
        .unwrap();

    let publish_actions = server
        .process_event(ServerEvent::FrameReceived { session_id: session_2, frame: kp_publish })
        .unwrap();

    // Should have a Log action for successful publish
    assert!(
        has_log_containing(&publish_actions, "KeyPackage published"),
        "KeyPackage publish should succeed"
    );

    // Step 4: Alice creates room
    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef_u128;
    server.create_room(room_id, session_1).unwrap(); // session_id, not user_id

    // Step 6: Alice fetches Bob's KeyPackage
    let kp_fetch =
        Payload::KeyPackageFetch(lockframe_proto::payloads::mls::KeyPackageFetchPayload {
            user_id: bob_user_id,
            key_package_bytes: vec![],
            hash_ref: vec![],
        })
        .into_frame(FrameHeader::new(Opcode::KeyPackageFetch))
        .unwrap();

    let fetch_actions = server
        .process_event(ServerEvent::FrameReceived { session_id: session_1, frame: kp_fetch })
        .unwrap();

    // Alice should receive KeyPackageFetch response
    let fetch_replies = frames_for_session(&fetch_actions, session_1);
    assert_eq!(fetch_replies.len(), 1, "Alice should receive KeyPackageFetch response");
    assert_eq!(fetch_replies[0].header.opcode_enum(), Some(Opcode::KeyPackageFetch));

    // Step 7: Alice sends Welcome to Bob
    // This is the critical test - Welcome should be routed to Bob's session

    let mut welcome_header = FrameHeader::new(Opcode::Welcome);
    welcome_header.set_room_id(room_id);
    welcome_header.set_sender_id(alice_user_id);
    welcome_header.set_recipient_id(bob_user_id); // Bob is the recipient

    let welcome_frame = Frame::new(welcome_header, vec![0xDE, 0xAD, 0xBE, 0xEF]); // Fake Welcome payload

    let welcome_actions = server
        .process_event(ServerEvent::FrameReceived { session_id: session_1, frame: welcome_frame })
        .unwrap();

    // Welcome should be routed to Bob's session (session_2), NOT broadcast
    let bob_welcome_frames = frames_for_session(&welcome_actions, session_2);

    assert!(
        !bob_welcome_frames.is_empty(),
        "Welcome frame MUST be routed to Bob's session ({session_2}). Got actions: {welcome_actions:?}"
    );

    assert_eq!(
        bob_welcome_frames[0].header.opcode_enum(),
        Some(Opcode::Welcome),
        "Bob should receive Welcome frame"
    );

    assert_eq!(
        bob_welcome_frames[0].header.recipient_id(),
        bob_user_id,
        "Welcome recipient_id should be Bob's user_id"
    );

    // Verify subscription via Log action
    assert!(
        has_log_containing(&welcome_actions, "subscribed to room"),
        "Should log that Bob was subscribed to room"
    );
}

#[test]
fn test_welcome_routing_fails_without_hello() {
    let env = SystemEnv::new();
    let storage = MemoryStorage::new();
    let mut server = ServerDriver::new(env, storage, DriverConfig::default());

    let session_1 = 1001;
    let session_2 = 1002;
    let alice_user_id = 42;
    let bob_user_id = 99;

    // Both connect
    server.process_event(ServerEvent::ConnectionAccepted { session_id: session_1 }).unwrap();
    server.process_event(ServerEvent::ConnectionAccepted { session_id: session_2 }).unwrap();

    // Only Alice sends Hello - Bob doesn't authenticate
    let alice_hello = Payload::Hello(Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(alice_user_id),
        auth_token: None,
    })
    .into_frame(FrameHeader::new(Opcode::Hello))
    .unwrap();

    server
        .process_event(ServerEvent::FrameReceived { session_id: session_1, frame: alice_hello })
        .unwrap();

    // Alice creates room
    let room_id = 0x1234_u128;
    server.create_room(room_id, session_1).unwrap(); // session_id, not user_id

    // Alice sends Welcome to Bob (who never authenticated)
    let mut welcome_header = FrameHeader::new(Opcode::Welcome);
    welcome_header.set_room_id(room_id);
    welcome_header.set_sender_id(alice_user_id);
    welcome_header.set_recipient_id(bob_user_id);

    let welcome_frame = Frame::new(welcome_header, vec![]);

    let actions = server
        .process_event(ServerEvent::FrameReceived { session_id: session_1, frame: welcome_frame })
        .unwrap();

    // Should have warning about recipient not connected
    assert!(
        has_log_containing(&actions, "not connected"),
        "Should log warning when recipient not authenticated"
    );

    // Bob should NOT receive the Welcome
    let bob_frames = frames_for_session(&actions, session_2);
    assert!(bob_frames.is_empty(), "Bob should NOT receive Welcome when not authenticated");
}
