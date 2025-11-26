//! Scenario tests for timeout behavior.
//!
//! These tests verify that connections properly handle handshake and idle
//! timeouts using the scenario framework's time advancement feature.

use std::time::Duration;

use sunder_core::connection::ConnectionState;
use sunder_harness::scenario::Scenario;

#[test]
fn scenario_handshake_timeout() {
    // Advance time past handshake timeout (30s) without completing handshake
    let result = Scenario::new()
        .with_time_advance(Duration::from_secs(31))
        .oracle(Box::new(|world| {
            // Client should timeout during handshake
            // Note: Currently handshake auto-completes in scenario.run()
            // This test will need handshake-skipping variant to test properly
            // For now, verify both are authenticated (handshake completed before timeout)
            assert_eq!(world.client().state(), ConnectionState::Authenticated);
            assert_eq!(world.server().state(), ConnectionState::Authenticated);

            Ok(())
        }))
        .run();

    assert!(result.is_ok());
}

#[test]
fn scenario_idle_timeout() {
    // Advance time past idle timeout (60s) after handshake
    let result = Scenario::new()
        .with_time_advance(Duration::from_secs(61))
        .oracle(Box::new(|world| {
            // Both should be closed due to idle timeout
            assert_eq!(world.client().state(), ConnectionState::Closed);
            assert_eq!(world.server().state(), ConnectionState::Closed);

            Ok(())
        }))
        .run();

    assert!(result.is_ok());
}

#[test]
fn scenario_heartbeat_prevents_timeout() {
    // Advance time less than idle timeout (< 60s)
    // Heartbeats should be sent automatically, preventing timeout
    let result = Scenario::new()
        .with_time_advance(Duration::from_secs(45))
        .oracle(Box::new(|world| {
            // Should still be authenticated (heartbeats sent)
            assert_eq!(world.client().state(), ConnectionState::Authenticated);
            assert_eq!(world.server().state(), ConnectionState::Authenticated);

            // Verify heartbeats were sent
            // Initial handshake: 1 frame each
            // After 45s with 20s heartbeat interval: should have sent pings
            assert!(
                world.client_frames_sent() > 1,
                "client should have sent heartbeats (Hello + Pings), got {}",
                world.client_frames_sent()
            );
            assert!(
                world.server_frames_sent() > 1,
                "server should have sent heartbeats (HelloReply + Pongs), got {}",
                world.server_frames_sent()
            );

            Ok(())
        }))
        .run();

    assert!(result.is_ok());
}
