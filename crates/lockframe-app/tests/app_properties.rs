//! Property-based tests for App state machine.
//!
//! Tests verify that invariants hold under arbitrary event sequences.
//! This ensures behavioral correctness across all possible execution paths.

use lockframe_app::{App, AppAction, AppEvent, Bridge};
use lockframe_harness::{
    ClientSnapshot, InvariantKind, InvariantRegistry, RoomSnapshot, SimEnv, SystemSnapshot,
};
use proptest::prelude::*;

/// Generate random app events.
fn event_strategy() -> impl Strategy<Value = AppEvent> {
    prop_oneof![
        1 => Just(AppEvent::Tick),
        1 => (1u16..200, 1u16..100).prop_map(|(c, r)| AppEvent::Resize(c, r)),
        2 => (1u128..1000).prop_map(|id| AppEvent::RoomJoined { room_id: id }),
        1 => (1u128..1000).prop_map(|id| AppEvent::RoomLeft { room_id: id }),
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

/// Process actions from App through Bridge and update App state.
fn process_actions(app: &mut App, bridge: &mut Bridge<SimEnv>, actions: Vec<AppAction>) {
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
}

/// Create a room using App API and process through Bridge.
fn create_room(app: &mut App, bridge: &mut Bridge<SimEnv>, room_id: u128) {
    let actions = app.create_room(room_id);
    process_actions(app, bridge, actions);
}

/// Send a message using App API and process through Bridge.
fn send_message(app: &mut App, bridge: &mut Bridge<SimEnv>, room_id: u128, content: &str) {
    let actions = app.send_message(room_id, content.as_bytes().to_vec());
    process_actions(app, bridge, actions);
}

proptest! {
    #[test]
    fn prop_app_invariants_hold(events in prop::collection::vec(event_strategy(), 0..50)) {
        let mut app = App::new("localhost:4433".into());
        let invariants = InvariantRegistry::standard();

        for event in events {
            let _ = app.handle(event.clone());
            let snapshot = snapshot_from_app(&app);
            prop_assert!(invariants.check_all(&snapshot).is_ok());
        }
    }

    #[test]
    fn prop_set_active_room_validates(room_count in 1usize..5, target in 0u128..10) {
        let mut app = App::new("localhost:4433".into());

        for i in 0..room_count {
            let _ = app.handle(AppEvent::RoomJoined { room_id: i as u128 });
        }

        app.set_active_room(target);

        if (target as usize) < room_count {
            prop_assert_eq!(app.active_room(), Some(target));
        } else {
            // First room is active on invalid ID
            prop_assert_eq!(app.active_room(), Some(0));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_app_bridge_invariants_hold(room_ids in prop::collection::vec(1u128..1000, 1..5)) {
        let env = SimEnv::with_seed(42);
        let mut app = App::new("localhost:4433".into());
        let mut bridge: Bridge<SimEnv> = Bridge::new(env, 1);
        let invariants = InvariantRegistry::standard();

        app.handle(AppEvent::Connected { session_id: 1, sender_id: 1 });

        for room_id in &room_ids {
            create_room(&mut app, &mut bridge, *room_id);
            prop_assert!(app.rooms().contains_key(room_id));

            let snapshot = snapshot_from_app(&app);
            prop_assert!(invariants.check_all(&snapshot).is_ok());
        }

        for room_id in &room_ids {
            prop_assert!(app.rooms().contains_key(room_id));
        }
    }
}

#[test]
fn test_invariant_violation_detected() {
    let snapshot = SystemSnapshot::single(
        ClientSnapshot::new(1).with_active_room(Some(999)), // Room doesn't exist
    );

    let invariants = InvariantRegistry::standard();
    let result = invariants.check_all(&snapshot);

    assert!(result.is_err());

    let violations = result.unwrap_err();
    assert!(violations.iter().any(|v| v.invariant == InvariantKind::ActiveRoomInRooms));
}

#[test]
fn test_epoch_monotonicity_violation_detected() {
    let mut client = ClientSnapshot::new(1);
    client.record_epoch(100, 5);
    client.record_epoch(100, 3); // Decreased

    let snapshot = SystemSnapshot::single(client);
    let invariants = InvariantRegistry::standard();
    let result = invariants.check_all(&snapshot);

    assert!(result.is_err());

    let violations = result.unwrap_err();
    assert!(violations.iter().any(|v| v.invariant == InvariantKind::EpochMonotonicity));
}

#[test]
fn test_basic_app_bridge_flow() {
    let env = SimEnv::with_seed(42);
    let mut app = App::new("localhost:4433".into());
    let mut bridge: Bridge<SimEnv> = Bridge::new(env, 1);
    let invariants = InvariantRegistry::standard();

    assert!(app.rooms().is_empty());
    assert!(app.active_room().is_none());

    app.handle(AppEvent::Connected { session_id: 1, sender_id: 1 });

    create_room(&mut app, &mut bridge, 100);
    assert!(app.rooms().contains_key(&100));
    assert_eq!(app.active_room(), Some(100));

    send_message(&mut app, &mut bridge, 100, "hello world");
    let frames = bridge.take_outgoing();
    assert!(!frames.is_empty());

    let snapshot = snapshot_from_app(&app);
    assert!(invariants.check_all(&snapshot).is_ok());
}
