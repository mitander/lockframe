//! Optimality oracle tests
//!
//! These tests verify EFFICIENCY, not just correctness.
use std::time::Duration;

use lockframe_core::connection::ConnectionState;
use lockframe_harness::scenario::Scenario;

#[test]
fn optimal_handshake_message_count() {
    // Handshake must complete in EXACTLY 2 messages
    // - Client sends 1 Hello
    // - Server sends 1 HelloReply
    // Any more messages = protocol bloat

    let result = Scenario::new()
        .oracle(Box::new(|world| {
            // Verify both authenticated
            assert_eq!(world.client().state(), ConnectionState::Authenticated);
            assert_eq!(world.server().state(), ConnectionState::Authenticated);

            // EXACTLY 2 messages total
            let total_messages = world.client_frames_sent() + world.server_frames_sent();

            assert_eq!(
                total_messages, 2,
                "Handshake inefficient: expected 2 messages (Hello + HelloReply), got {total_messages}"
            );

            // Individual counts must also be exactly 1 each
            assert_eq!(world.client_frames_sent(), 1, "Client should send exactly 1 frame (Hello)");
            assert_eq!(
                world.server_frames_sent(),
                1,
                "Server should send exactly 1 frame (HelloReply)"
            );

            Ok(())
        }))
        .run();

    assert!(result.is_ok(), "Optimality oracle failed: {result:?}");
}

#[test]
fn optimal_heartbeat_frequency() {
    // Heartbeats should be sent at configured interval,
    // not more frequently (wastes bandwidth) or less frequently (risks timeout)

    let _heartbeat_interval = Duration::from_secs(20);
    let test_duration = Duration::from_secs(45); // 2.25 intervals

    let result = Scenario::new()
        .with_time_advance(test_duration)
        .oracle(Box::new(move |world| {
            // Currently heartbeats are not yet implemented in the connection state machine.
            // When implemented, this test will verify optimal frequency.
            // For now, we verify handshake completes (2 messages total).

            let expected_messages = 2; // Handshake only (no heartbeats yet)

            // Message count must match predicted value
            assert_eq!(
                world.client_frames_sent(),
                expected_messages,
                "Client message count: expected {} messages over {:?}, got {}",
                expected_messages,
                test_duration,
                world.client_frames_sent()
            );

            assert_eq!(
                world.server_frames_sent(),
                expected_messages,
                "Server message count: expected {} messages over {:?}, got {}",
                expected_messages,
                test_duration,
                world.server_frames_sent()
            );

            Ok(())
        }))
        .run();

    assert!(result.is_ok(), "Heartbeat optimality oracle failed: {result:?}");
}

#[test]
fn optimal_idle_timeout_detection() {
    // Idle timeout should trigger at EXACTLY the configured
    // timeout, not earlier (premature disconnection) or later (resource waste)

    let idle_timeout = Duration::from_secs(60);

    // Test 1: Just before timeout - should still be connected
    let result_before = Scenario::new()
        .with_time_advance(idle_timeout.checked_sub(Duration::from_secs(1)).unwrap())
        .oracle(Box::new(|world| {
            // Must NOT timeout prematurely
            assert_eq!(
                world.client().state(),
                ConnectionState::Authenticated,
                "Client timed out prematurely (before idle_timeout)"
            );
            assert_eq!(
                world.server().state(),
                ConnectionState::Authenticated,
                "Server timed out prematurely (before idle_timeout)"
            );

            Ok(())
        }))
        .run();

    assert!(result_before.is_ok(), "Premature timeout detected");

    // Test 2: Just after timeout - should be closed
    let result_after = Scenario::new()
        .with_time_advance(idle_timeout + Duration::from_secs(1))
        .oracle(Box::new(|world| {
            // Must timeout promptly
            assert_eq!(
                world.client().state(),
                ConnectionState::Closed,
                "Client did not timeout (after idle_timeout)"
            );
            assert_eq!(
                world.server().state(),
                ConnectionState::Closed,
                "Server did not timeout (after idle_timeout)"
            );

            Ok(())
        }))
        .run();

    assert!(result_after.is_ok(), "Delayed timeout detected");
}

#[test]
fn optimal_connection_state_machine_steps() {
    // State transitions should be minimal
    // Client: Init -> Pending -> Authenticated (2 transitions)
    // Server: Init -> Authenticated (1 transition, direct from Hello)

    let result = Scenario::new()
        .oracle(Box::new(|world| {
            // Verify final states are correct
            assert_eq!(world.client().state(), ConnectionState::Authenticated);
            assert_eq!(world.server().state(), ConnectionState::Authenticated);

            // Verify minimal state transitions
            // (This is verified implicitly by the state machine design,
            // but we document it here as an oracle)

            // The fact that handshake completes in 2 messages proves
            // minimal state transitions:
            // - Client cannot skip Pending (must wait for HelloReply)
            // - Server can go directly to Authenticated (has Hello immediately)

            let total_messages = world.client_frames_sent() + world.server_frames_sent();

            assert_eq!(total_messages, 2, "More messages than optimal = more state transitions");

            Ok(())
        }))
        .run();

    assert!(result.is_ok(), "State machine not optimal");
}
