//! Property-based tests for App state machine.
//!
//! Tests verify that invariants hold under arbitrary event sequences.
//! This ensures behavioral correctness across all possible execution paths.

use lockframe_app::{App, AppAction, AppEvent, Bridge, KeyInput};
use lockframe_harness::{ClientSnapshot, InvariantRegistry, RoomSnapshot, SimEnv, SystemSnapshot};
use proptest::prelude::*;

/// Generate random printable characters for input.
fn printable_char() -> impl Strategy<Value = char> {
    prop::char::range(' ', '~')
}

/// Generate random key inputs.
fn key_strategy() -> impl Strategy<Value = KeyInput> {
    prop_oneof![
        4 => printable_char().prop_map(KeyInput::Char),
        1 => Just(KeyInput::Enter),
        1 => Just(KeyInput::Backspace),
        1 => Just(KeyInput::Tab),
        1 => Just(KeyInput::Esc),
        1 => Just(KeyInput::Left),
        1 => Just(KeyInput::Right),
    ]
}

/// Generate random app events.
fn event_strategy() -> impl Strategy<Value = AppEvent> {
    prop_oneof![
        8 => key_strategy().prop_map(AppEvent::Key),
        1 => Just(AppEvent::Tick),
        1 => (1u16..200, 1u16..100).prop_map(|(c, r)| AppEvent::Resize(c, r)),
    ]
}

/// Extract state snapshot from App for invariant checking.
fn snapshot_from_app(app: &App) -> SystemSnapshot {
    let mut rooms = std::collections::HashMap::new();
    for (room_id, room_state) in app.rooms() {
        rooms.insert(
            *room_id,
            RoomSnapshot::with_epoch(0) // App doesn't expose epoch
                .with_members(room_state.members.iter().copied())
                .with_message_count(room_state.messages.len()),
        );
    }

    let client = ClientSnapshot {
        id: 0, // App doesn't track client ID
        active_room: app.active_room(),
        rooms,
        epoch_history: std::collections::HashMap::new(),
    };

    SystemSnapshot::single(client)
}

proptest! {
    /// App invariants hold under arbitrary event sequences.
    ///
    /// Verifies that active_room is always in rooms (or None).
    #[test]
    fn prop_app_invariants_hold(events in prop::collection::vec(event_strategy(), 0..50)) {
        let mut app = App::new("localhost:4433".into());
        let invariants = InvariantRegistry::standard();

        for event in events {
            let _ = app.handle(event.clone());

            let snapshot = snapshot_from_app(&app);
            prop_assert!(
                invariants.check_all(&snapshot).is_ok(),
                "Invariant violated after {:?}", event
            );
        }
    }

    /// Input buffer operations are consistent.
    ///
    /// After typing characters and pressing enter, buffer should be empty.
    #[test]
    fn prop_input_buffer_clears_on_enter(chars in prop::collection::vec(printable_char(), 1..20)) {
        let mut app = App::new("localhost:4433".into());

        for c in &chars {
            let _ = app.handle(AppEvent::Key(KeyInput::Char(*c)));
        }

        // Buffer should contain the characters
        let buffer_len = app.input_buffer().len();
        prop_assert_eq!(buffer_len, chars.len());

        let _ = app.handle(AppEvent::Key(KeyInput::Enter));

        // Buffer should be empty
        prop_assert!(app.input_buffer().is_empty());
    }

    /// Cursor stays within buffer bounds.
    #[test]
    fn prop_cursor_within_bounds(events in prop::collection::vec(key_strategy(), 0..100)) {
        let mut app = App::new("localhost:4433".into());

        for key in events {
            let _ = app.handle(AppEvent::Key(key));

            let cursor = app.input_cursor();
            let buffer_len = app.input_buffer().len();

            prop_assert!(
                cursor <= buffer_len,
                "Cursor {} exceeds buffer length {}",
                cursor,
                buffer_len
            );
        }
    }
}

/// Helper to inject a command into App and process through Bridge.
fn inject_command(app: &mut App, bridge: &mut Bridge<SimEnv>, cmd: &str) {
    for c in cmd.chars() {
        app.handle(AppEvent::Key(KeyInput::Char(c)));
    }
    let actions = app.handle(AppEvent::Key(KeyInput::Enter));

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
            _ => {},
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// App+Bridge invariants hold under command sequences.
    #[test]
    fn prop_app_bridge_invariants_hold(room_ids in prop::collection::vec(1u128..1000, 1..5)) {
        let env = SimEnv::with_seed(42);
        let mut app = App::new("localhost:4433".into());
        let mut bridge: Bridge<SimEnv> = Bridge::new(env, 1);
        let invariants = InvariantRegistry::standard();

        // Simulate connected
        app.handle(AppEvent::Connected { session_id: 1, sender_id: 1 });

        // Create rooms
        for room_id in &room_ids {
            inject_command(&mut app, &mut bridge, &format!("/create {}", room_id));

            // Verify room was created
            prop_assert!(app.rooms().contains_key(room_id));

            // Check invariants
            let snapshot = snapshot_from_app(&app);
            prop_assert!(
                invariants.check_all(&snapshot).is_ok(),
                "Invariant violated after creating room {}", room_id
            );
        }

        // Verify all rooms still exist
        for room_id in &room_ids {
            prop_assert!(
                app.rooms().contains_key(room_id),
                "Room {} should still exist",
                room_id
            );
        }
    }
}

#[test]
fn test_invariant_violation_detected() {
    // Manually create invalid state to verify invariants catch it
    let snapshot = SystemSnapshot::single(
        ClientSnapshot::new(1).with_active_room(Some(999)), // Room doesn't exist
    );

    let invariants = InvariantRegistry::standard();
    let result = invariants.check_all(&snapshot);

    assert!(result.is_err(), "Should detect active_room not in rooms");

    let violations = result.unwrap_err();
    assert!(
        violations.iter().any(|v| v.invariant == "active_room_in_rooms"),
        "Should have active_room_in_rooms violation"
    );
}

#[test]
fn test_epoch_monotonicity_violation_detected() {
    let mut client = ClientSnapshot::new(1);
    client.record_epoch(100, 5);
    client.record_epoch(100, 3); // Decreased!

    let snapshot = SystemSnapshot::single(client);
    let invariants = InvariantRegistry::standard();
    let result = invariants.check_all(&snapshot);

    assert!(result.is_err(), "Should detect epoch decrease");

    let violations = result.unwrap_err();
    assert!(
        violations.iter().any(|v| v.invariant == "epoch_monotonicity"),
        "Should have epoch_monotonicity violation"
    );
}

#[test]
fn test_basic_app_bridge_flow() {
    let env = SimEnv::with_seed(42);
    let mut app = App::new("localhost:4433".into());
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, 1);
    let invariants = InvariantRegistry::standard();

    // Initial state - no rooms
    assert!(app.rooms().is_empty());
    assert!(app.active_room().is_none());

    // Connect
    app.handle(AppEvent::Connected { session_id: 1, sender_id: 1 });

    // Create a room
    inject_command(&mut app, &mut bridge, "/create 100");

    // Verify room exists and is active
    assert!(app.rooms().contains_key(&100));
    assert_eq!(app.active_room(), Some(100));

    // Send a message
    inject_command(&mut app, &mut bridge, "hello world");

    // Should have produced outgoing frames
    let frames = bridge.take_outgoing();
    assert!(!frames.is_empty());

    // Snapshot should pass invariants
    let snapshot = snapshot_from_app(&app);
    assert!(invariants.check_all(&snapshot).is_ok());
}
