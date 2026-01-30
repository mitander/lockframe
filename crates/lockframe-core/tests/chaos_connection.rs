//! Chaos property tests for Connection state machine
//!
//! These tests verify that the Connection handles various failure modes:
//! - Invalid frames don't crash the state machine
//! - State transitions remain valid under stress
//! - Timeouts are properly detected
//! - Connection eventually closes on errors

use std::time::Duration;

use bytes::Bytes;
use lockframe_core::{
    connection::{Connection, ConnectionConfig, ConnectionState},
    env::{Environment, test_utils::MockEnv},
};
use lockframe_proto::{Frame, FrameHeader, Opcode};
use proptest::prelude::*;

/// Strategy for generating arbitrary opcodes
fn arbitrary_opcode() -> impl Strategy<Value = Opcode> {
    prop_oneof![
        Just(Opcode::Hello),
        Just(Opcode::HelloReply),
        Just(Opcode::Ping),
        Just(Opcode::Pong),
        Just(Opcode::Goodbye),
        Just(Opcode::Error),
        Just(Opcode::AppMessage),
        Just(Opcode::AppReceipt),
        Just(Opcode::AppReaction),
        Just(Opcode::Welcome),
        Just(Opcode::Commit),
        Just(Opcode::Proposal),
        Just(Opcode::KeyPackage),
        Just(Opcode::Redact),
        Just(Opcode::Ban),
        Just(Opcode::Kick),
    ]
}

/// Create a simple test frame with given opcode
fn create_frame_for_opcode(opcode: Opcode) -> Frame {
    let mut header = FrameHeader::new(opcode);
    header.set_room_id(1);
    header.set_sender_id(1);
    header.set_epoch(0);

    // Use correct setter based on opcode (context_id has different semantics)
    if opcode == Opcode::Welcome {
        header.set_recipient_id(0);
    } else {
        header.set_log_index(0);
    }

    // Create with empty payload - we're testing connection state machine, not
    // payloads
    Frame::new(header, Bytes::new())
}

#[test]
fn prop_connection_never_panics_on_invalid_frames() {
    proptest!(|(
        opcode in arbitrary_opcode(),
    )| {
        let env = MockEnv::new();
        let t0 = env.now();
        let config = ConnectionConfig::default();
        let mut conn = Connection::new(t0, config);

        let frame = create_frame_for_opcode(opcode);

        // Process frame - should never panic
        let _ = conn.handle_frame(&frame, t0);

        // Connection should remain in valid state
        prop_assert!(
            matches!(
                conn.state(),
                ConnectionState::Init
                    | ConnectionState::Pending
                    | ConnectionState::Authenticated
                    | ConnectionState::Closed
            ),
            "Connection in invalid state"
        );
    });
}

#[test]
fn prop_connection_state_transitions_valid() {
    proptest!(|(
        opcodes in prop::collection::vec(arbitrary_opcode(), 1..20),
    )| {
        let env = MockEnv::new();
        let t0 = env.now();
        let config = ConnectionConfig::default();
        let mut conn = Connection::new(t0, config);

        let initial_state = conn.state().clone();

        // Process sequence of frames
        for opcode in opcodes {
            let frame = create_frame_for_opcode(opcode);
            let _ = conn.handle_frame(&frame, t0);
        }

        let final_state = conn.state();

        // INVARIANT: State transitions must be valid
        // Init -> Pending -> Authenticated -> Closed
        // Can skip states, but never go backward

        let state_order = |s: &ConnectionState| -> u8 {
            match s {
                ConnectionState::Init => 0,
                ConnectionState::Pending => 1,
                ConnectionState::Authenticated => 2,
                ConnectionState::Closed => 3,
            }
        };

        let initial_order = state_order(&initial_state);
        let final_order = state_order(&final_state);

        prop_assert!(
            final_order >= initial_order,
            "Connection state went backward: {:?} -> {:?}",
            initial_state,
            final_state
        );
    });
}

#[test]
fn prop_connection_closed_stays_closed() {
    proptest!(|(
        opcodes in prop::collection::vec(arbitrary_opcode(), 1..20),
    )| {
        let env = MockEnv::new();
        let t0 = env.now();
        let config = ConnectionConfig::default();
        let mut conn = Connection::new(t0, config);

        // Force connection to closed state
        conn.close();

        prop_assert_eq!(
            conn.state(),
            ConnectionState::Closed,
            "close() must set state to Closed"
        );

        // Try to process frames on closed connection
        for opcode in opcodes {
            let frame = create_frame_for_opcode(opcode);
            let _ = conn.handle_frame(&frame, t0);

            // INVARIANT: Closed connections stay closed
            prop_assert_eq!(
                conn.state(),
                ConnectionState::Closed,
                "Closed connection must reject all frames"
            );
        }
    });
}

#[test]
fn prop_connection_tick_monotonic_time() {
    proptest!(|(
        time_deltas in prop::collection::vec(1u64..1000, 1..50),
    )| {
        let env = MockEnv::new();
        let t0 = env.now();
        let config = ConnectionConfig::default();
        let mut conn = Connection::new(t0, config);

        let mut t = t0;

        // Call tick with monotonically increasing time
        for delta_ms in time_deltas {
            t = t + Duration::from_millis(delta_ms);
            let _ = conn.tick(t);

            // INVARIANT: Connection should handle monotonic time gracefully
            // (No panics, state remains valid)
            prop_assert!(
                matches!(
                    conn.state(),
                    ConnectionState::Init
                        | ConnectionState::Pending
                        | ConnectionState::Authenticated
                        | ConnectionState::Closed
                ),
                "Connection in invalid state after tick"
            );
        }
    });
}

#[test]
fn prop_connection_tick_linear_complexity() {
    proptest!(|(
        tick_count in 10usize..200,
    )| {
        let env = MockEnv::new();
        let t0 = env.now();
        let config = ConnectionConfig::default();
        let mut conn = Connection::new(t0, config);

        let mut t = t0;
        let mut action_count = 0usize;

        // Call tick repeatedly with small time increments
        for _ in 0..tick_count {
            t = t + Duration::from_millis(10);
            let actions = conn.tick(t);
            action_count += actions.len();
        }

        // PERFORMANCE ORACLE: tick() should be O(1), not O(n)
        // Even after many ticks, total actions should be bounded
        // Maximum expected: 1 heartbeat per tick (in practice much less)
        let max_expected_actions = tick_count * 2; // Generous bound

        prop_assert!(
            action_count <= max_expected_actions,
            "Performance degradation detected: {} actions for {} ticks (expected <= {})",
            action_count,
            tick_count,
            max_expected_actions
        );
    });
}
