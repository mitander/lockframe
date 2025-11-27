//! Property-based tests for Connection state machine.
//!
//! These tests use proptest to verify invariants hold for all possible inputs:
//! - State transitions are valid
//! - Timeouts occur at expected times
//! - Frame handling is consistent
//! - No panics on arbitrary inputs

use std::time::{Duration, Instant};

use proptest::prelude::*;
use sunder_core::{
    connection::{Connection, ConnectionAction, ConnectionConfig, ConnectionState},
    error::ConnectionError,
};
use sunder_proto::{FrameHeader, Opcode, Payload, payloads::session::HelloReply};

// Strategy for generating valid ConnectionConfigs
fn config_strategy() -> impl Strategy<Value = ConnectionConfig> {
    (1u64..=120, 1u64..=300, 1u64..=60).prop_map(|(handshake, idle, heartbeat)| ConnectionConfig {
        handshake_timeout: Duration::from_secs(handshake),
        idle_timeout: Duration::from_secs(idle),
        heartbeat_interval: Duration::from_secs(heartbeat),
    })
}

// Strategy for generating time advances (0-500 seconds)
fn time_advance_strategy() -> impl Strategy<Value = Duration> {
    (0u64..=500).prop_map(Duration::from_secs)
}

// Strategy for generating session IDs
fn session_id_strategy() -> impl Strategy<Value = u64> {
    any::<u64>()
}

/// Property: send_hello() only succeeds from Init state
#[test]
fn prop_send_hello_only_from_init() {
    proptest!(|(config in config_strategy())| {
        let now = Instant::now();
        let mut conn = Connection::new(now, config);

        // First call should succeed
        assert!(conn.send_hello(now).is_ok());
        assert_eq!(conn.state(), ConnectionState::Pending);

        // Second call should fail (not in Init)
        let result = conn.send_hello(now);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectionError::InvalidState { .. }));
    });
}

/// Property: State never goes backwards (except to Closed)
#[test]
fn prop_state_never_goes_backward() {
    proptest!(|(config in config_strategy(), session_id in session_id_strategy())| {
        let now = Instant::now();
        let mut conn = Connection::new(now, config);

        // Track state progression
        let mut states = vec![conn.state()];

        // Init -> Pending
        let _ = conn.send_hello(now);
        states.push(conn.state());

        // Pending -> Authenticated
        let hello_reply = Payload::HelloReply(HelloReply {
            session_id,
            capabilities: vec![],
            challenge: None,
        });
        let frame = hello_reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        let _ = conn.handle_frame(&frame, now);
        states.push(conn.state());

        // Verify progression
        assert_eq!(states[0], ConnectionState::Init);
        assert_eq!(states[1], ConnectionState::Pending);
        assert_eq!(states[2], ConnectionState::Authenticated);
    });
}

/// Property: Timeout always closes connection
#[test]
fn prop_timeout_always_closes() {
    proptest!(|(config in config_strategy())| {
        let now = Instant::now();
        let mut conn = Connection::new(now, config.clone());

        // Test handshake timeout
        let _ = conn.send_hello(now);
        assert_eq!(conn.state(), ConnectionState::Pending);

        let future = now + config.handshake_timeout + Duration::from_secs(1);
        let actions = conn.tick(future);

        assert_eq!(conn.state(), ConnectionState::Closed);
        assert!(!actions.is_empty());
        assert!(actions.iter().any(|a| matches!(a, ConnectionAction::Close { .. })));
    });
}

/// Property: Idle timeout only occurs in Authenticated state
#[test]
fn prop_idle_timeout_only_authenticated() {
    proptest!(|(
        config in config_strategy(),
        session_id in session_id_strategy(),
        advance in time_advance_strategy()
    )| {
        let now = Instant::now();

        // Test Init state - no timeout
        let mut conn = Connection::new(now, config.clone());
        let future = now + advance;
        let actions = conn.tick(future);
        // Init state never times out
        assert_eq!(conn.state(), ConnectionState::Init);
        assert!(actions.is_empty());

        // Test Authenticated state - timeout if advance > idle_timeout
        let mut conn = Connection::new(now, config.clone());
        let _ = conn.send_hello(now);
        let hello_reply = Payload::HelloReply(HelloReply {
            session_id,
            capabilities: vec![],
            challenge: None,
        });
        let frame = hello_reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        let _ = conn.handle_frame(&frame, now);
        assert_eq!(conn.state(), ConnectionState::Authenticated);

        let future = now + advance;
        let actions = conn.tick(future);

        if advance > config.idle_timeout {
            assert_eq!(conn.state(), ConnectionState::Closed);
            assert!(actions.iter().any(|a| matches!(a, ConnectionAction::Close { .. })));
        } else {
            assert_eq!(conn.state(), ConnectionState::Authenticated);
        }
    });
}

/// Property: Heartbeats only sent when Authenticated
#[test]
fn prop_heartbeats_only_authenticated() {
    proptest!(|(
        config in config_strategy(),
        session_id in session_id_strategy()
    )| {
        let now = Instant::now();

        // Test Init state - no heartbeat
        let mut conn = Connection::new(now, config.clone());
        let future = now + config.heartbeat_interval + Duration::from_secs(1);
        let actions = conn.tick(future);

        let has_heartbeat = actions.iter().any(|a| {
            matches!(a, ConnectionAction::SendFrame(frame)
                if frame.header.opcode_enum() == Some(Opcode::Ping))
        });
        assert!(!has_heartbeat, "Init state should not send heartbeats");

        // Test Pending state - no heartbeat
        let mut conn = Connection::new(now, config.clone());
        let _ = conn.send_hello(now);
        let future = now + config.heartbeat_interval + Duration::from_secs(1);
        let actions = conn.tick(future);

        let has_heartbeat = actions.iter().any(|a| {
            matches!(a, ConnectionAction::SendFrame(frame)
                if frame.header.opcode_enum() == Some(Opcode::Ping))
        });
        assert!(!has_heartbeat, "Pending state should not send heartbeats");

        // Test Authenticated state - should send heartbeat
        // NOTE: heartbeat_interval must be < idle_timeout or timeout wins
        let mut conn = Connection::new(now, config.clone());
        let _ = conn.send_hello(now);
        let hello_reply = Payload::HelloReply(HelloReply {
            session_id,
            capabilities: vec![],
            challenge: None,
        });
        let frame = hello_reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        let _ = conn.handle_frame(&frame, now);

        // Advance time to heartbeat interval, but not past idle timeout
        // This test only makes sense if heartbeat_interval < idle_timeout
        if config.heartbeat_interval < config.idle_timeout {
            let future = now + config.heartbeat_interval + Duration::from_secs(1);
            let actions = conn.tick(future);

            let has_heartbeat = actions.iter().any(|a| {
                matches!(a, ConnectionAction::SendFrame(frame)
                    if frame.header.opcode_enum() == Some(Opcode::Ping))
            });
            assert!(has_heartbeat, "Authenticated state should send heartbeats when heartbeat_interval < idle_timeout");
        }
    });
}

/// Property: Session ID never changes once set
#[test]
fn prop_session_id_immutable() {
    proptest!(|(
        config in config_strategy(),
        session_id1 in session_id_strategy(),
        session_id2 in session_id_strategy()
    )| {
        let now = Instant::now();
        let mut conn = Connection::new(now, config);

        // Client flow
        let _ = conn.send_hello(now);

        let hello_reply1 = Payload::HelloReply(HelloReply {
            session_id: session_id1,
            capabilities: vec![],
            challenge: None,
        });
        let frame1 = hello_reply1.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        let _ = conn.handle_frame(&frame1, now);

        assert_eq!(conn.session_id(), Some(session_id1));

        // Try to set different session ID - should be ignored
        let hello_reply2 = Payload::HelloReply(HelloReply {
            session_id: session_id2,
            capabilities: vec![],
            challenge: None,
        });
        let frame2 = hello_reply2.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();

        // Attempting to handle HelloReply in Authenticated state should error
        let result = conn.handle_frame(&frame2, now);
        assert!(result.is_err());

        // Session ID should remain unchanged
        assert_eq!(conn.session_id(), Some(session_id1));
    });
}

/// Property: Activity updates reset timeout
#[test]
fn prop_activity_resets_timeout() {
    proptest!(|(
        config in config_strategy(),
        session_id in session_id_strategy(),
        advance1 in 1u64..=50,
        advance2 in 1u64..=50
    )| {
        let now = Instant::now();
        let mut conn = Connection::new(now, config.clone());

        // Get to Authenticated state
        let _ = conn.send_hello(now);
        let hello_reply = Payload::HelloReply(HelloReply {
            session_id,
            capabilities: vec![],
            challenge: None,
        });
        let frame = hello_reply.into_frame(FrameHeader::new(Opcode::HelloReply)).unwrap();
        let _ = conn.handle_frame(&frame, now);

        // Advance time but not past timeout
        let t1 = now + Duration::from_secs(advance1);
        conn.update_activity(t1);

        // Advance again but not past timeout from t1
        let t2 = t1 + Duration::from_secs(advance2);
        let actions = conn.tick(t2);

        // Should not timeout if total advance < idle_timeout
        let total = Duration::from_secs(advance1 + advance2);
        if total <= config.idle_timeout {
            assert_eq!(conn.state(), ConnectionState::Authenticated);
            assert!(actions.iter().all(|a| !matches!(a, ConnectionAction::Close { .. })));
        }
    });
}

/// Property: Error classification is consistent
#[test]
fn prop_error_classification_consistent() {
    proptest!(|(elapsed in 1u64..=1000)| {
        let timeout_err = ConnectionError::HandshakeTimeout {
            elapsed: Duration::from_secs(elapsed),
        };
        assert!(timeout_err.is_transient());

        let idle_err = ConnectionError::IdleTimeout {
            elapsed: Duration::from_secs(elapsed),
        };
        assert!(idle_err.is_transient());

        let protocol_err = ConnectionError::Protocol("test".to_string());
        assert!(!protocol_err.is_transient());

        let transport_err = ConnectionError::Transport("test".to_string());
        assert!(!transport_err.is_transient());

        let version_err = ConnectionError::UnsupportedVersion(99);
        assert!(!version_err.is_transient());
    });
}

/// Property: Closed state is terminal
#[test]
fn prop_closed_is_terminal() {
    proptest!(|(
        config in config_strategy(),
        advance in time_advance_strategy()
    )| {
        let now = Instant::now();
        let mut conn = Connection::new(now, config);

        // Force to closed state
        conn.close();
        assert_eq!(conn.state(), ConnectionState::Closed);

        // Try various operations
        let future = now + advance;

        // tick() should do nothing
        let actions = conn.tick(future);
        assert!(actions.is_empty());
        assert_eq!(conn.state(), ConnectionState::Closed);

        // send_hello() should fail
        let result = conn.send_hello(future);
        assert!(result.is_err());
        assert_eq!(conn.state(), ConnectionState::Closed);

        // State should remain Closed
        assert_eq!(conn.state(), ConnectionState::Closed);
    });
}
