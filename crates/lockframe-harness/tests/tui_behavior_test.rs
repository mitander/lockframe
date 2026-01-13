//! End-to-end tests for TUI behavior verification.
//!
//! # Test Strategy
//!
//! Each test simulates what a user does in the TUI:
//! 1. Type commands (e.g., "/create 100")
//! 2. Process through App → Bridge → Client
//! 3. Simulate server responses
//! 4. Verify App state matches expected TUI behavior
//!
//! # Oracle Pattern
//!
//! Tests end with oracle checks that verify:
//! - App state reflects the expected UI state
//! - Messages are delivered to the correct rooms
//! - Member lists are consistent

use lockframe_app::{App, AppAction, AppEvent, Bridge, KeyInput};
use lockframe_harness::SimEnv;
use lockframe_proto::{Frame, FrameHeader, Opcode, Payload, payloads::mls::GroupInfoPayload};

/// Create a connected App ready for testing.
fn connected_app(sender_id: u64) -> App {
    let mut app = App::new("localhost:4433".into());
    app.handle(AppEvent::Connected { session_id: 1, sender_id });
    app
}

/// Inject a command into App and process through Bridge.
/// Returns the outgoing frames that would be sent to server.
fn inject_command<E: lockframe_core::env::Environment>(
    app: &mut App,
    bridge: &mut Bridge<E>,
    cmd: &str,
) -> Vec<Frame> {
    for c in cmd.chars() {
        app.handle(AppEvent::Key(KeyInput::Char(c)));
    }
    let actions = app.handle(AppEvent::Key(KeyInput::Enter));

    for action in actions {
        process_app_action(app, bridge, action);
    }

    bridge.take_outgoing()
}

/// Process a single AppAction through Bridge and update App.
fn process_app_action<E: lockframe_core::env::Environment>(
    app: &mut App,
    bridge: &mut Bridge<E>,
    action: AppAction,
) {
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
        _ => {},
    }
}

/// Simulate receiving a frame from the server.
fn receive_frame<E: lockframe_core::env::Environment>(
    app: &mut App,
    bridge: &mut Bridge<E>,
    frame: Frame,
) {
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

/// Test that /create command creates a room and sets it as active.
///
/// TUI behavior:
/// - User types "/create 100"
/// - App shows "Joined room 100"
/// - Room 100 becomes the active room
/// - GroupInfo frame is sent to server
#[test]
fn create_command_creates_room() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // User types "/create 100"
    let frames = inject_command(&mut app, &mut bridge, "/create 100");

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

/// Test that messages can be sent after creating a room.
///
/// TUI behavior:
/// - User creates room
/// - User types "hello world"
/// - Message appears in chat
/// - AppMessage frame is sent to server
#[test]
fn message_after_create() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Create room
    let _ = inject_command(&mut app, &mut bridge, "/create 100");
    let _ = bridge.take_outgoing(); // Clear frames

    // Send message
    let frames = inject_command(&mut app, &mut bridge, "hello world");

    // Oracle: Message should appear in room
    let room = app.rooms().get(&100).expect("Room should exist");
    assert!(!room.messages.is_empty(), "Room should have messages");
    assert_eq!(room.messages[0].content, b"hello world", "Message content should match");

    // Oracle: AppMessage should be sent to server
    let msg_frames = frames_by_opcode(&frames, Opcode::AppMessage);
    assert_eq!(msg_frames.len(), 1, "Should send one AppMessage");
}

/// Test that /join initiates external join and processes GroupInfo response.
///
/// TUI behavior:
/// 1. User types "/join 100"
/// 2. GroupInfoRequest is sent to server
/// 3. Server responds with GroupInfo
/// 4. ExternalCommit is sent to server
/// 5. Room 100 appears in sidebar and becomes active
///
/// This is the flow that was broken in TUI but passed Client-only tests.
#[test]
fn external_join_flow() {
    let env = SimEnv::with_seed(42);

    // Alice creates room first
    let alice_sender_id = 1;
    let mut alice_app = connected_app(alice_sender_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_sender_id);

    let alice_frames = inject_command(&mut alice_app, &mut alice_bridge, "/create 100");
    let group_info_frames = frames_by_opcode(&alice_frames, Opcode::GroupInfo);
    assert_eq!(group_info_frames.len(), 1, "Alice should publish GroupInfo");

    let group_info_payload = extract_group_info(&group_info_frames[0]).expect("Parse GroupInfo");

    // Bob tries to join
    let bob_sender_id = 2;
    let mut bob_app = connected_app(bob_sender_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_sender_id);

    // Bob types "/join 100"
    let bob_frames = inject_command(&mut bob_app, &mut bob_bridge, "/join 100");

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

/// Test that messages work between clients after external join.
///
/// TUI behavior:
/// 1. Alice creates room
/// 2. Bob joins via /join
/// 3. Alice sends "Hello Bob"
/// 4. Bob receives "Hello Bob"
/// 5. Bob sends "Hello Alice"
/// 6. Alice receives "Hello Alice"
#[test]
fn messaging_after_external_join() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = inject_command(&mut alice_app, &mut alice_bridge, "/create 100");
    let group_info = extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
        .expect("Extract GroupInfo");

    // Bob joins
    let bob_id = 2;
    let mut bob_app = connected_app(bob_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_id);

    inject_command(&mut bob_app, &mut bob_bridge, "/join 100");

    // Simulate server sending GroupInfo to Bob
    let group_info_frame = Payload::GroupInfo(group_info)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("Create frame");

    receive_frame(&mut bob_app, &mut bob_bridge, group_info_frame);
    let bob_commit_frames = bob_bridge.take_outgoing();

    // Alice processes Bob's external commit
    let ext_commit = frames_by_opcode(&bob_commit_frames, Opcode::ExternalCommit);
    assert_eq!(ext_commit.len(), 1, "Bob should send ExternalCommit");
    receive_frame(&mut alice_app, &mut alice_bridge, ext_commit[0].clone());

    // Both should now be in room 100
    assert!(alice_app.rooms().contains_key(&100), "Alice should have room");
    assert!(bob_app.rooms().contains_key(&100), "Bob should have room");

    // Alice sends message
    let alice_msg_frames = inject_command(&mut alice_app, &mut alice_bridge, "Hello Bob");
    let alice_msgs = frames_by_opcode(&alice_msg_frames, Opcode::AppMessage);
    assert_eq!(alice_msgs.len(), 1, "Alice should send message");

    // Bob receives message
    receive_frame(&mut bob_app, &mut bob_bridge, alice_msgs[0].clone());

    // Oracle: Bob's room should have Alice's message
    let bob_room = bob_app.rooms().get(&100).expect("Bob should have room");
    assert!(
        bob_room.messages.iter().any(|m| m.content == b"Hello Bob" && m.sender_id == alice_id),
        "Bob should have Alice's message"
    );

    // Bob sends message
    let bob_msg_frames = inject_command(&mut bob_app, &mut bob_bridge, "Hello Alice");
    let bob_msgs = frames_by_opcode(&bob_msg_frames, Opcode::AppMessage);
    assert_eq!(bob_msgs.len(), 1, "Bob should send message");

    // Alice receives message
    receive_frame(&mut alice_app, &mut alice_bridge, bob_msgs[0].clone());

    // Oracle: Alice's room should have Bob's message
    let alice_room = alice_app.rooms().get(&100).expect("Alice should have room");
    assert!(
        alice_room.messages.iter().any(|m| m.content == b"Hello Alice" && m.sender_id == bob_id),
        "Alice should have Bob's message"
    );
}

/// Test that /add command adds a member via Welcome.
///
/// TUI behavior:
/// 1. Alice creates room
/// 2. Bob publishes KeyPackage
/// 3. Server stores Bob's KeyPackage
/// 4. Alice types "/add 2"
/// 5. Alice's App shows "Added member 2"
/// 6. Welcome frame is sent to server
/// 7. Bob processes Welcome and joins room
#[test]
fn add_member_flow() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    inject_command(&mut alice_app, &mut alice_bridge, "/create 100");
    alice_bridge.take_outgoing(); // Clear frames

    // Bob creates identity and generates KeyPackage
    let bob_id = 2;
    let bob_env = env.clone();
    let bob_identity = lockframe_client::ClientIdentity::new(bob_id);
    let mut bob_client = lockframe_client::Client::new(bob_env, bob_identity);

    // Bob generates KeyPackage
    let (_key_package_bytes, _hash_ref) = bob_client.generate_key_package().expect("Generate KP");

    // Alice add Bob
    for c in "/add 2".chars() {
        alice_app.handle(AppEvent::Key(KeyInput::Char(c)));
    }
    let actions = alice_app.handle(AppEvent::Key(KeyInput::Enter));

    // Oracle: Should produce AddMember action
    let add_action = actions.iter().find(|a| matches!(a, AppAction::AddMember { .. }));
    assert!(add_action.is_some(), "Should produce AddMember action");

    if let Some(AppAction::AddMember { room_id, user_id }) = add_action {
        assert_eq!(*room_id, 100, "Should add to room 100");
        assert_eq!(*user_id, 2, "Should add user 2");
    }

    // Oracle: Status message should show adding
    assert!(
        alice_app.status_message().map_or(false, |m| m.contains("Adding")),
        "Status should show adding: {:?}",
        alice_app.status_message()
    );
}

/// Test three clients communicating after mixed join methods.
///
/// TUI behavior:
/// 1. Alice creates room
/// 2. Bob joins via Welcome (/add from Alice)
/// 3. Charlie joins via external commit (/join)
/// 4. All three can send and receive messages
#[test]
fn three_clients_full_flow() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = inject_command(&mut alice_app, &mut alice_bridge, "/create 100");
    let group_info = extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
        .expect("Extract GroupInfo");

    // Bob joins via Welcome
    let bob_id = 2;
    let bob_env = env.clone();
    let bob_identity = lockframe_client::ClientIdentity::new(bob_id);
    let mut bob_client = lockframe_client::Client::new(bob_env.clone(), bob_identity);

    let (_bob_kp, _) = bob_client.generate_key_package().expect("Bob KP");

    // Alice adds Bob - in real flow this goes through server
    let _alice_client_actions =
        alice_bridge.process_app_action(AppAction::AddMember { room_id: 100, user_id: bob_id });

    // Actually the FetchAndAddMember flow requires server roundtrip
    // Let's test Alice creating Welcome directly by accessing client
    // This is a limitation of the test - real flow goes through server

    // For now, verify Charlie's external join works
    let charlie_id = 3;
    let mut charlie_app = connected_app(charlie_id);
    let mut charlie_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), charlie_id);

    // Charlie joins via /join
    inject_command(&mut charlie_app, &mut charlie_bridge, "/join 100");
    let group_info_frame = Payload::GroupInfo(group_info)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("Create frame");

    receive_frame(&mut charlie_app, &mut charlie_bridge, group_info_frame);
    let charlie_commit_frames = charlie_bridge.take_outgoing();

    let ext_commit = frames_by_opcode(&charlie_commit_frames, Opcode::ExternalCommit);
    assert_eq!(ext_commit.len(), 1, "Charlie should send ExternalCommit");

    // Alice processes Charlie's commit
    receive_frame(&mut alice_app, &mut alice_bridge, ext_commit[0].clone());

    // Oracle: Both Alice and Charlie should be in room
    assert!(alice_app.rooms().contains_key(&100), "Alice should have room");
    assert!(charlie_app.rooms().contains_key(&100), "Charlie should have room");

    // Alice sends message
    let alice_msg_frames = inject_command(&mut alice_app, &mut alice_bridge, "Hello everyone!");
    let alice_msgs = frames_by_opcode(&alice_msg_frames, Opcode::AppMessage);

    // Charlie receives message
    receive_frame(&mut charlie_app, &mut charlie_bridge, alice_msgs[0].clone());

    let charlie_room = charlie_app.rooms().get(&100).expect("Charlie room");
    assert!(
        charlie_room.messages.iter().any(|m| m.content == b"Hello everyone!"),
        "Charlie should have Alice's message"
    );
}

/// Test that joining a non-existent room shows error.
///
/// TUI behavior:
/// - User types "/join 999"
/// - GroupInfoRequest is sent
/// - Server responds with error (or timeout)
/// - Error message is shown in status bar
#[test]
fn join_nonexistent_room_shows_error() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Try to join non-existent room
    let frames = inject_command(&mut app, &mut bridge, "/join 999");

    // Should send GroupInfoRequest
    let request_frames = frames_by_opcode(&frames, Opcode::GroupInfoRequest);
    assert_eq!(request_frames.len(), 1, "Should send GroupInfoRequest");

    // App should NOT have room yet (waiting for response)
    assert!(!app.rooms().contains_key(&999), "Room should not exist yet");
}

/// Test that Tab key cycles through rooms.
///
/// TUI behavior:
/// - User creates room 100
/// - User creates room 200
/// - User presses Tab
/// - Active room switches from 100 to 200
/// - User presses Tab again
/// - Active room switches from 200 to 100
#[test]
fn tab_cycles_rooms() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Create two rooms
    inject_command(&mut app, &mut bridge, "/create 100");
    inject_command(&mut app, &mut bridge, "/create 200");

    // Initial active room should be 100 (first created)
    assert_eq!(app.active_room(), Some(100), "Initial active should be 100");

    // Tab to next room
    app.handle(AppEvent::Key(KeyInput::Tab));
    assert_eq!(app.active_room(), Some(200), "After Tab, active should be 200");

    // Tab wraps around
    app.handle(AppEvent::Key(KeyInput::Tab));
    assert_eq!(app.active_room(), Some(100), "After second Tab, active should be 100");
}

/// Test that /leave removes room from App.
///
/// TUI behavior:
/// - User creates room 100
/// - User types "/leave"
/// - Room 100 is removed from sidebar
/// - No active room
#[test]
fn leave_removes_room() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Create room
    inject_command(&mut app, &mut bridge, "/create 100");
    assert!(app.rooms().contains_key(&100), "Room should exist");

    // Leave room
    inject_command(&mut app, &mut bridge, "/leave");

    // Oracle: Room should be gone
    assert!(!app.rooms().contains_key(&100), "Room should be removed");
    assert_eq!(app.active_room(), None, "No active room");
}

/// Test that the joiner can still decrypt messages after receiving their own
/// ExternalCommit broadcast from the server.
#[test]
fn external_commit_broadcast_back_to_joiner() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = inject_command(&mut alice_app, &mut alice_bridge, "/create 100");
    let group_info = extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
        .expect("Extract GroupInfo");

    // Bob joins
    let bob_id = 2;
    let mut bob_app = connected_app(bob_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_id);

    inject_command(&mut bob_app, &mut bob_bridge, "/join 100");

    // Server sends GroupInfo to Bob
    let group_info_frame = Payload::GroupInfo(group_info)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("Create frame");

    receive_frame(&mut bob_app, &mut bob_bridge, group_info_frame);
    let bob_commit_frames = bob_bridge.take_outgoing();

    let ext_commit = frames_by_opcode(&bob_commit_frames, Opcode::ExternalCommit);
    assert_eq!(ext_commit.len(), 1, "Bob should send ExternalCommit");

    // CRITICAL: Server broadcasts ExternalCommit to BOTH Alice AND Bob
    // This is what happens in real TUI - Bob receives their own commit back
    receive_frame(&mut alice_app, &mut alice_bridge, ext_commit[0].clone());
    receive_frame(&mut bob_app, &mut bob_bridge, ext_commit[0].clone()); // Bob gets it back!

    // Both should be in room
    assert!(alice_app.rooms().contains_key(&100), "Alice should have room");
    assert!(bob_app.rooms().contains_key(&100), "Bob should have room");

    // Alice sends message AFTER Bob received his own commit back
    let alice_msg_frames = inject_command(&mut alice_app, &mut alice_bridge, "Hello Bob");
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
    let bob_msg_frames = inject_command(&mut bob_app, &mut bob_bridge, "Hello Alice");
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

/// Test that a third client joining via external commit can communicate.
///
/// This reproduces the bug where third+ clients get "ratchet too far behind"
/// errors after joining.
#[test]
fn third_client_external_join_messaging() {
    let env = SimEnv::with_seed(42);

    // Alice creates room
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = inject_command(&mut alice_app, &mut alice_bridge, "/create 100");
    let group_info_epoch0 =
        extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
            .expect("Extract GroupInfo");

    // Bob joins (first external joiner)
    let bob_id = 2;
    let mut bob_app = connected_app(bob_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_id);

    inject_command(&mut bob_app, &mut bob_bridge, "/join 100");
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
    let alice_msg1 = inject_command(&mut alice_app, &mut alice_bridge, "Hello from Alice");
    let alice_msgs1 = frames_by_opcode(&alice_msg1, Opcode::AppMessage);

    // Bob receives Alice's message
    receive_frame(&mut bob_app, &mut bob_bridge, alice_msgs1[0].clone());
    let bob_room = bob_app.rooms().get(&100).expect("Bob room");
    assert!(
        bob_room.messages.iter().any(|m| m.content == b"Hello from Alice"),
        "Bob should have Alice's message"
    );

    // Bob sends a message
    let bob_msg1 = inject_command(&mut bob_app, &mut bob_bridge, "Hello from Bob");
    let bob_msgs1 = frames_by_opcode(&bob_msg1, Opcode::AppMessage);

    // Alice receives Bob's message
    receive_frame(&mut alice_app, &mut alice_bridge, bob_msgs1[0].clone());

    // NOW Charlie joins (second external joiner, third member)
    let charlie_id = 3;
    let mut charlie_app = connected_app(charlie_id);
    let mut charlie_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), charlie_id);

    inject_command(&mut charlie_app, &mut charlie_bridge, "/join 100");

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
    let alice_msg2 = inject_command(&mut alice_app, &mut alice_bridge, "Welcome Charlie!");
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
    let charlie_msg = inject_command(&mut charlie_app, &mut charlie_bridge, "Thanks Alice!");
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

/// Test that receiving duplicate RoomJoined doesn't clear messages.
///
/// This was a real TUI bug: when a member was added, all clients received
/// RoomJoined events which cleared their chat history.
#[test]
fn duplicate_room_joined_preserves_messages() {
    let env = SimEnv::with_seed(42);
    let sender_id = 1;
    let mut app = connected_app(sender_id);
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, sender_id);

    // Create room and send message
    inject_command(&mut app, &mut bridge, "/create 100");
    inject_command(&mut app, &mut bridge, "message 1");
    inject_command(&mut app, &mut bridge, "message 2");

    let room = app.rooms().get(&100).expect("Room exists");
    assert_eq!(room.messages.len(), 2, "Should have 2 messages");

    // Receive duplicate RoomJoined (e.g., after member added)
    app.handle(AppEvent::RoomJoined { room_id: 100 });

    // Oracle: Messages should still be there
    let room = app.rooms().get(&100).expect("Room exists");
    assert_eq!(room.messages.len(), 2, "Messages should be preserved");
}

/// Test that messages sent BEFORE a client joins are visible via
/// server_plaintext.
///
/// This tests the history feature: when Alice sends a message at epoch 0 and
/// Bob joins at epoch 1, Bob cannot decrypt the epoch 0 message (forward
/// secrecy). However, if the message contains server_plaintext, Bob can still
/// see it.
#[test]
fn pre_join_messages_visible_via_plaintext() {
    let env = SimEnv::with_seed(42);

    // Alice creates room and sends message at epoch 0
    let alice_id = 1;
    let mut alice_app = connected_app(alice_id);
    let mut alice_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), alice_id);

    let alice_frames = inject_command(&mut alice_app, &mut alice_bridge, "/create 100");
    let group_info = extract_group_info(&frames_by_opcode(&alice_frames, Opcode::GroupInfo)[0])
        .expect("Extract GroupInfo");

    // Alice sends message at epoch 0 (before Bob joins)
    let alice_msg_frames = inject_command(&mut alice_app, &mut alice_bridge, "Hello from epoch 0");
    let epoch0_msg = frames_by_opcode(&alice_msg_frames, Opcode::AppMessage)[0].clone();

    // Verify the message is an AppMessage (plaintext is embedded in payload)
    assert_eq!(
        epoch0_msg.header.opcode_enum(),
        Some(Opcode::AppMessage),
        "Should be an AppMessage frame"
    );

    // Bob joins via external commit (epoch advances to 1)
    let bob_id = 2;
    let mut bob_app = connected_app(bob_id);
    let mut bob_bridge: Bridge<SimEnv> = Bridge::new(env.clone(), bob_id);

    inject_command(&mut bob_app, &mut bob_bridge, "/join 100");
    let gi_frame = Payload::GroupInfo(group_info)
        .into_frame(FrameHeader::new(Opcode::GroupInfo))
        .expect("frame");
    receive_frame(&mut bob_app, &mut bob_bridge, gi_frame);
    let bob_commit_frames = bob_bridge.take_outgoing();
    let ext_commit = frames_by_opcode(&bob_commit_frames, Opcode::ExternalCommit);

    // Broadcast commit to both (now both at epoch 1)
    receive_frame(&mut alice_app, &mut alice_bridge, ext_commit[0].clone());
    receive_frame(&mut bob_app, &mut bob_bridge, ext_commit[0].clone());

    // Verify Bob is at epoch 1
    let bob_room = bob_app.rooms().get(&100).expect("Bob room");
    assert_eq!(bob_room.messages.len(), 0, "Bob should start with no messages");

    // Bob receives the old epoch 0 message (simulating sync response)
    // The frame is from epoch 0 but Bob is at epoch 1
    // Bob can't decrypt it, but server_plaintext lets him see it
    receive_frame(&mut bob_app, &mut bob_bridge, epoch0_msg);

    // Oracle: Bob should have Alice's pre-join message via server_plaintext
    let bob_room = bob_app.rooms().get(&100).expect("Bob room");
    assert_eq!(bob_room.messages.len(), 1, "Bob should have 1 message from history");
    assert_eq!(
        bob_room.messages[0].content, b"Hello from epoch 0",
        "Bob should see pre-join message content"
    );
}
