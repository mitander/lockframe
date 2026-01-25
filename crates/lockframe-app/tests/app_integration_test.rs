//! Integration tests for App and Bridge behavior.
//!
//! # Oracle Pattern
//!
//! Tests end with oracle checks that verify:
//! - App state reflects expected state
//! - Messages are delivered to the correct rooms
//! - Member lists are consistent

use lockframe_app::{App, AppAction, AppEvent, Bridge};
use lockframe_core::env::Environment;
use lockframe_harness::SimEnv;
use lockframe_proto::{Frame, FrameHeader, Opcode, Payload, payloads::mls::GroupInfoPayload};

/// Create a connected App ready for testing.
fn connected_app(sender_id: u64) -> App {
    let mut app = App::new("localhost:4433".into());
    app.handle(AppEvent::Connected { session_id: 1, sender_id });
    app
}

/// Process actions from App through Bridge and update App state.
fn process_actions<E: Environment>(
    app: &mut App,
    bridge: &mut Bridge<E>,
    actions: Vec<AppAction>,
) -> Vec<Frame> {
    for action in actions {
        match action {
            AppAction::CreateRoom { .. }
            | AppAction::JoinRoom { .. }
            | AppAction::LeaveRoom { .. }
            | AppAction::SendMessage { .. }
            | AppAction::PublishKeyPackage
            | AppAction::AddMember { .. } => {
                let events = bridge.process_app_action(action);
                for event in events {
                    app.handle(event);
                }
            },
            AppAction::Render | AppAction::Quit | AppAction::Connect { .. } => {},
        }
    }

    bridge.take_outgoing()
}

/// Create a room using App API and process through Bridge.
fn create_room<E: Environment>(app: &mut App, bridge: &mut Bridge<E>, room_id: u128) -> Vec<Frame> {
    let actions = app.create_room(room_id);
    process_actions(app, bridge, actions)
}

/// Join a room using App API and process through Bridge.
fn join_room<E: Environment>(app: &mut App, bridge: &mut Bridge<E>, room_id: u128) -> Vec<Frame> {
    let actions = app.join_room(room_id);
    process_actions(app, bridge, actions)
}

/// Leave a room using App API and process through Bridge.
fn leave_room<E: Environment>(app: &mut App, bridge: &mut Bridge<E>, room_id: u128) -> Vec<Frame> {
    let actions = app.leave_room(room_id);
    process_actions(app, bridge, actions)
}

/// Send a message using App API and process through Bridge.
fn send_message<E: Environment>(
    app: &mut App,
    bridge: &mut Bridge<E>,
    room_id: u128,
    content: &str,
) -> Vec<Frame> {
    let actions = app.send_message(room_id, content.as_bytes().to_vec());
    process_actions(app, bridge, actions)
}

/// Simulate receiving a frame from the server.
fn receive_frame<E: Environment>(app: &mut App, bridge: &mut Bridge<E>, frame: Frame) {
    let events = bridge.handle_frame(frame);
    for event in events {
        app.handle(event);
    }
}

/// Extract frames with a specific opcode.
fn frames_by_opcode(frames: &[Frame], opcode: Opcode) -> Vec<Frame> {
    frames.iter().filter(|f| f.header.opcode_enum() == Some(opcode)).cloned().collect()
}

/// Extract GroupInfo payload from a frame.
fn extract_group_info(frame: &Frame) -> Option<GroupInfoPayload> {
    match Payload::from_frame(frame.clone()).ok()? {
        Payload::GroupInfo(p) => Some(p),
        _ => None,
    }
}

#[test]
fn join_nonexistent_room_shows_error() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Try to join non-existent room
    let frames = join_room(&mut app, &mut bridge, 999);

    // Should send GroupInfoRequest
    let request_frames = frames_by_opcode(&frames, Opcode::GroupInfoRequest);
    assert_eq!(request_frames.len(), 1);

    // App should NOT have room yet (waiting for response)
    assert!(!app.rooms().contains_key(&999));
}

#[test]
fn create_command_creates_room() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    let frames = create_room(&mut app, &mut bridge, 100);

    // Oracle: App state should show room created
    assert!(app.rooms().contains_key(&100), "Room 100 should exist in App");
    assert_eq!(app.active_room(), Some(100), "Room 100 should be active");

    // Oracle: GroupInfo should be sent to server
    let group_info_frames = frames_by_opcode(&frames, Opcode::GroupInfo);
    assert!(!group_info_frames.is_empty(), "Should send GroupInfo to server");

    // Oracle: Status message should indicate success
    assert!(
        app.status_message().map_or(false, |m| m.contains("Joined room")),
        "Status should show joined: {:?}",
        app.status_message()
    );
}

#[test]
fn external_join_flow() {
    let env = SimEnv::with_seed(42);

    // Alice creates room first
    let alice_sender_id = 1;
    let mut alice_app = connected_app(alice_sender_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_sender_id);

    let alice_frames = create_room(&mut alice_app, &mut alice_bridge, 100);
    let group_info_frames = frames_by_opcode(&alice_frames, Opcode::GroupInfo);
    assert_eq!(group_info_frames.len(), 1, "Alice should publish GroupInfo");

    let group_info_payload = extract_group_info(&group_info_frames[0]).expect("Parse GroupInfo");

    // Bob tries to join
    let bob_sender_id = 2;
    let mut bob_app = connected_app(bob_sender_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_sender_id);

    // Bob types "/join 100"
    let bob_frames = join_room(&mut bob_app, &mut bob_bridge, 100);

    // Should send GroupInfoRequest
    let request_frames = frames_by_opcode(&bob_frames, Opcode::GroupInfoRequest);
    assert_eq!(request_frames.len(), 1, "Bob should send GroupInfoRequest");

    // Server responds with GroupInfo
    let group_info_response = Payload::GroupInfo(group_info_payload)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("Create GroupInfo frame");

    receive_frame(&mut bob_app, &mut bob_bridge, group_info_response);
    let response_frames = bob_bridge.take_outgoing();

    // Oracle: ExternalCommit should be sent
    let commit_frames = frames_by_opcode(&response_frames, Opcode::ExternalCommit);
    assert_eq!(commit_frames.len(), 1, "Bob should send ExternalCommit");

    // Oracle: Bob's App should show room joined
    assert!(bob_app.rooms().contains_key(&100), "Bob should have room 100");
    assert_eq!(bob_app.active_room(), Some(100), "Room 100 should be Bob's active room");
}

#[test]
fn set_active_room_switches_rooms() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Create two rooms
    create_room(&mut app, &mut bridge, 100);
    create_room(&mut app, &mut bridge, 200);

    // Initial active room should be 100 (first created)
    assert_eq!(app.active_room(), Some(100), "Initial active should be 100");

    // Switch to room 200
    app.set_active_room(200);
    assert_eq!(app.active_room(), Some(200), "After set, active should be 200");

    // Switch back to room 100
    app.set_active_room(100);
    assert_eq!(app.active_room(), Some(100), "After second set, active should be 100");
}

#[test]
fn leave_removes_room() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Create room
    create_room(&mut app, &mut bridge, 100);
    assert!(app.rooms().contains_key(&100), "Room should exist");

    // Leave room
    leave_room(&mut app, &mut bridge, 100);

    // Oracle: Room should be gone
    assert!(!app.rooms().contains_key(&100), "Room should be removed");
    assert_eq!(app.active_room(), None, "No active room");
}

#[test]
fn external_commit_broadcast_back_to_joiner() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = create_room(&mut alice_app, &mut alice_bridge, 100);
    let group_info = extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
        .expect("Extract GroupInfo");

    // Bob joins
    let bob_id = 2;
    let mut bob_app = connected_app(bob_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_id);

    join_room(&mut bob_app, &mut bob_bridge, 100);

    // Server sends GroupInfo to Bob
    let group_info_frame = Payload::GroupInfo(group_info)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("Create frame");

    receive_frame(&mut bob_app, &mut bob_bridge, group_info_frame);
    let bob_commit_frames = bob_bridge.take_outgoing();

    let ext_commit = frames_by_opcode(&bob_commit_frames, Opcode::ExternalCommit);
    assert_eq!(ext_commit.len(), 1, "Bob should send ExternalCommit");

    // Server broadcasts ExternalCommit to BOTH Alice AND Bob
    // This is what happens in real TUI - Bob receives their own commit back
    receive_frame(&mut alice_app, &mut alice_bridge, ext_commit[0].clone());
    receive_frame(&mut bob_app, &mut bob_bridge, ext_commit[0].clone()); // Bob gets it back!

    // Both should be in room
    assert!(alice_app.rooms().contains_key(&100), "Alice should have room");
    assert!(bob_app.rooms().contains_key(&100), "Bob should have room");

    // Alice sends message AFTER Bob received his own commit back
    let alice_msg_frames = send_message(&mut alice_app, &mut alice_bridge, 100, "Hello Bob");
    let alice_msgs = frames_by_opcode(&alice_msg_frames, Opcode::AppMessage);
    assert_eq!(alice_msgs.len(), 1, "Alice should send message");

    // Bob receives message - THIS WAS FAILING because sender keys got reset
    receive_frame(&mut bob_app, &mut bob_bridge, alice_msgs[0].clone());

    // Oracle: Bob should have Alice's message
    let bob_room = bob_app.rooms().get(&100).expect("Bob should have room");
    assert!(
        bob_room.messages.iter().any(|m| m.content == b"Hello Bob" && m.sender_id == alice_id),
        "Bob should have Alice's message. Messages: {:?}",
        bob_room.messages.iter().map(|m| String::from_utf8_lossy(&m.content)).collect::<Vec<_>>()
    );

    // Bob sends message
    let bob_msg_frames = send_message(&mut bob_app, &mut bob_bridge, 100, "Hello Alice");
    let bob_msgs = frames_by_opcode(&bob_msg_frames, Opcode::AppMessage);
    assert_eq!(bob_msgs.len(), 1, "Bob should send message");

    // Alice receives message
    receive_frame(&mut alice_app, &mut alice_bridge, bob_msgs[0].clone());

    // Oracle: Alice should have Bob's message
    let alice_room = alice_app.rooms().get(&100).expect("Alice should have room");
    assert!(
        alice_room.messages.iter().any(|m| m.content == b"Hello Alice" && m.sender_id == bob_id),
        "Alice should have Bob's message. Messages: {:?}",
        alice_room.messages.iter().map(|m| String::from_utf8_lossy(&m.content)).collect::<Vec<_>>()
    );
}

#[test]
fn third_client_external_join_messaging() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = create_room(&mut alice_app, &mut alice_bridge, 100);
    let group_info_epoch0 =
        extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
            .expect("Extract GroupInfo");

    // Bob joins (first external joiner)
    let bob_id = 2;
    let mut bob_app = connected_app(bob_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_id);

    join_room(&mut bob_app, &mut bob_bridge, 100);
    let gi_frame = Payload::GroupInfo(group_info_epoch0)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("frame");
    receive_frame(&mut bob_app, &mut bob_bridge, gi_frame);
    let bob_commit_frames = bob_bridge.take_outgoing();
    let bob_ext_commit = frames_by_opcode(&bob_commit_frames, Opcode::ExternalCommit);
    assert_eq!(bob_ext_commit.len(), 1);

    // Bob also publishes GroupInfo at the new epoch
    let bob_gi_frames = frames_by_opcode(&bob_commit_frames, Opcode::GroupInfo);
    assert_eq!(bob_gi_frames.len(), 1, "Bob should publish GroupInfo after external join");
    let group_info_epoch1 = extract_group_info(&bob_gi_frames[0]).expect("Extract Bob's GroupInfo");

    // Server broadcasts Bob's ExternalCommit to Alice and Bob
    receive_frame(&mut alice_app, &mut alice_bridge, bob_ext_commit[0].clone());
    receive_frame(&mut bob_app, &mut bob_bridge, bob_ext_commit[0].clone());

    // Alice sends a message at epoch 1
    let alice_msg1 = send_message(&mut alice_app, &mut alice_bridge, 100, "Hello from Alice");
    let alice_msgs1 = frames_by_opcode(&alice_msg1, Opcode::AppMessage);

    // Bob receives Alice's message
    receive_frame(&mut bob_app, &mut bob_bridge, alice_msgs1[0].clone());
    let bob_room = bob_app.rooms().get(&100).expect("Bob room");
    assert!(
        bob_room.messages.iter().any(|m| m.content == b"Hello from Alice"),
        "Bob should have Alice's message"
    );

    // Bob sends a message
    let bob_msg1 = send_message(&mut bob_app, &mut bob_bridge, 100, "Hello from Bob");
    let bob_msgs1 = frames_by_opcode(&bob_msg1, Opcode::AppMessage);

    // Alice receives Bob's message
    receive_frame(&mut alice_app, &mut alice_bridge, bob_msgs1[0].clone());

    // NOW Charlie joins (second external joiner, third member)
    let charlie_id = 3;
    let mut charlie_app = connected_app(charlie_id);
    let mut charlie_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), charlie_id);

    join_room(&mut charlie_app, &mut charlie_bridge, 100);

    // Charlie needs GroupInfo at current epoch (1)
    // Server provides Bob's published GroupInfo (stored from his external join)
    let charlie_gi_frame = Payload::GroupInfo(group_info_epoch1.clone())
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("frame");
    receive_frame(&mut charlie_app, &mut charlie_bridge, charlie_gi_frame);
    let charlie_commit_frames = charlie_bridge.take_outgoing();
    let charlie_ext_commit = frames_by_opcode(&charlie_commit_frames, Opcode::ExternalCommit);
    assert_eq!(charlie_ext_commit.len(), 1, "Charlie should send ExternalCommit");

    // Server broadcasts Charlie's ExternalCommit to ALL (Alice, Bob, Charlie)
    receive_frame(&mut alice_app, &mut alice_bridge, charlie_ext_commit[0].clone());
    receive_frame(&mut bob_app, &mut bob_bridge, charlie_ext_commit[0].clone());
    receive_frame(&mut charlie_app, &mut charlie_bridge, charlie_ext_commit[0].clone());

    // All three should be in the room now
    assert!(alice_app.rooms().contains_key(&100), "Alice should have room");
    assert!(bob_app.rooms().contains_key(&100), "Bob should have room");
    assert!(charlie_app.rooms().contains_key(&100), "Charlie should have room");

    // Alice sends a message (this is where the bug manifests)
    let alice_msg2 = send_message(&mut alice_app, &mut alice_bridge, 100, "Welcome Charlie!");
    let alice_msgs2 = frames_by_opcode(&alice_msg2, Opcode::AppMessage);
    assert_eq!(alice_msgs2.len(), 1, "Alice should send message");

    // Charlie receives Alice's message - THIS IS WHERE IT FAILS
    receive_frame(&mut charlie_app, &mut charlie_bridge, alice_msgs2[0].clone());

    let charlie_room = charlie_app.rooms().get(&100).expect("Charlie room");
    assert!(
        charlie_room
            .messages
            .iter()
            .any(|m| m.content == b"Welcome Charlie!" && m.sender_id == alice_id),
        "Charlie should have Alice's message. Got: {:?}",
        charlie_room
            .messages
            .iter()
            .map(|m| format!("{}: {}", m.sender_id, String::from_utf8_lossy(&m.content)))
            .collect::<Vec<_>>()
    );

    // Charlie sends a message
    let charlie_msg = send_message(&mut charlie_app, &mut charlie_bridge, 100, "Thanks Alice!");
    let charlie_msgs = frames_by_opcode(&charlie_msg, Opcode::AppMessage);
    assert_eq!(charlie_msgs.len(), 1, "Charlie should send message");

    // Alice and Bob receive Charlie's message
    receive_frame(&mut alice_app, &mut alice_bridge, charlie_msgs[0].clone());
    receive_frame(&mut bob_app, &mut bob_bridge, charlie_msgs[0].clone());

    let alice_room = alice_app.rooms().get(&100).expect("Alice room");
    assert!(
        alice_room
            .messages
            .iter()
            .any(|m| m.content == b"Thanks Alice!" && m.sender_id == charlie_id),
        "Alice should have Charlie's message"
    );

    let bob_room = bob_app.rooms().get(&100).expect("Bob room");
    assert!(
        bob_room
            .messages
            .iter()
            .any(|m| m.content == b"Thanks Alice!" && m.sender_id == charlie_id),
        "Bob should have Charlie's message"
    );
}

#[test]
fn sync_request_sent_on_join() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = create_room(&mut alice_app, &mut alice_bridge, 100);
    let group_info = extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
        .expect("Extract GroupInfo");

    // Bob joins
    let bob_id = 2;
    let mut bob_app = connected_app(bob_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_id);

    join_room(&mut bob_app, &mut bob_bridge, 100);
    let gi_frame = Payload::GroupInfo(group_info)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("frame");

    receive_frame(&mut bob_app, &mut bob_bridge, gi_frame);
    let bob_frames = bob_bridge.take_outgoing();

    // Bob should send ExternalCommit AND SyncRequest
    let ext_commits = frames_by_opcode(&bob_frames, Opcode::ExternalCommit);
    let sync_requests = frames_by_opcode(&bob_frames, Opcode::SyncRequest);

    assert_eq!(ext_commits.len(), 1, "Bob should send ExternalCommit");
    assert_eq!(sync_requests.len(), 1, "Bob should send SyncRequest for historical messages");

    // Verify the SyncRequest is for room 100
    assert_eq!(sync_requests[0].header.room_id(), 100, "SyncRequest should be for room 100");
}

#[test]
fn same_epoch_messages_work() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = create_room(&mut alice_app, &mut alice_bridge, 100);
    let group_info = extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
        .expect("Extract GroupInfo");

    // Bob joins
    let bob_id = 2;
    let mut bob_app = connected_app(bob_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_id);

    join_room(&mut bob_app, &mut bob_bridge, 100);
    let gi_frame = Payload::GroupInfo(group_info)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("frame");
    receive_frame(&mut bob_app, &mut bob_bridge, gi_frame);
    let bob_commit_frames = bob_bridge.take_outgoing();
    let ext_commit = frames_by_opcode(&bob_commit_frames, Opcode::ExternalCommit);

    // Broadcast commit to both
    receive_frame(&mut alice_app, &mut alice_bridge, ext_commit[0].clone());
    receive_frame(&mut bob_app, &mut bob_bridge, ext_commit[0].clone());

    // Alice sends message at current epoch (epoch 1)
    let alice_msg = send_message(&mut alice_app, &mut alice_bridge, 100, "Hello at epoch 1");
    let alice_msgs = frames_by_opcode(&alice_msg, Opcode::AppMessage);

    // Bob receives message
    receive_frame(&mut bob_app, &mut bob_bridge, alice_msgs[0].clone());

    // Oracle: Bob should have Alice's message
    let bob_room = bob_app.rooms().get(&100).expect("Bob room");
    assert!(
        bob_room.messages.iter().any(|m| m.content == b"Hello at epoch 1"),
        "Bob should receive messages from current epoch"
    );
}

#[test]
fn duplicate_room_joined_preserves_messages() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Create room and send message
    create_room(&mut app, &mut bridge, 100);
    send_message(&mut app, &mut bridge, 100, "message 1");
    send_message(&mut app, &mut bridge, 100, "message 2");

    let room = app.rooms().get(&100).expect("Room exists");
    assert_eq!(room.messages.len(), 2, "Should have 2 messages");

    // Receive duplicate RoomJoined (e.g., after member added)
    app.handle(AppEvent::RoomJoined { room_id: 100 });

    // Oracle: Messages should still be there
    let room = app.rooms().get(&100).expect("Room exists");
    assert_eq!(room.messages.len(), 2, "Messages should be preserved");
}

#[test]
fn add_member_command_generates_frames() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Create room and add member
    create_room(&mut app, &mut bridge, 100);
    let actions = app.add_member(100, 2);

    // Oracle: UI binding should return AddMember action
    assert!(actions.iter().any(|a| matches!(a, AppAction::AddMember { room_id: 100, user_id: 2 })),);

    // Process through Bridge
    let frames = process_actions(&mut app, &mut bridge, actions);

    // Oracle: Bridge should trigger Client to generate frames
    assert!(!frames.is_empty(), "add_member should generate network frames");

    let kp_fetch_frames = frames_by_opcode(&frames, Opcode::KeyPackageFetch);
    assert_eq!(kp_fetch_frames.len(), 1, "Should fetch key package for user 2");
}
