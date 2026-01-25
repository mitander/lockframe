//! Integration tests for KeyPackage publish/fetch flow.
//!
//! Tests the complete multi-client join flow:
//! 1. Client B publishes KeyPackage to server
//! 2. Client A fetches KeyPackage for user_id B
//! 3. Server routes Welcome to B after A adds them

use lockframe_core::env::test_utils::MockEnv;
use lockframe_proto::{
    FrameHeader, Opcode, Payload,
    payloads::mls::{KeyPackageFetchPayload, KeyPackagePublishRequest},
};
use lockframe_server::{DriverConfig, MemoryStorage, ServerAction, ServerDriver, ServerEvent};

fn create_driver() -> ServerDriver<MockEnv, MemoryStorage> {
    let env = MockEnv::with_crypto_rng();
    let storage = MemoryStorage::new();
    let config = DriverConfig::default();
    ServerDriver::new(env, storage, config)
}

/// Test that fetching a non-existent KeyPackage returns an error.
#[test]
fn keypackage_fetch_not_found() {
    let mut driver = create_driver();

    let client_session = 1001;
    let nonexistent_user = 9999;

    // Connect and authenticate
    driver
        .process_event(ServerEvent::ConnectionAccepted { session_id: client_session })
        .expect("accept");

    let hello = Payload::Hello(lockframe_proto::payloads::session::Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(1000),
        auth_token: None,
    });
    let hello_frame =
        hello.into_frame(FrameHeader::new(Opcode::Hello)).expect("create hello frame");
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: client_session,
            frame: hello_frame,
        })
        .expect("auth");

    // Try to fetch KeyPackage for user that hasn't published
    let fetch_payload = Payload::KeyPackageFetch(KeyPackageFetchPayload {
        user_id: nonexistent_user,
        key_package_bytes: vec![],
        hash_ref: vec![],
    });
    let fetch_frame = fetch_payload
        .into_frame(FrameHeader::new(Opcode::KeyPackageFetch))
        .expect("create fetch frame");

    let actions = driver
        .process_event(ServerEvent::FrameReceived {
            session_id: client_session,
            frame: fetch_frame,
        })
        .expect("fetch");

    // Should send error response
    let error_frame = actions
        .iter()
        .find_map(|a| match a {
            ServerAction::SendToSession { session_id, frame } if *session_id == client_session => {
                Some(frame)
            },
            _ => None,
        })
        .expect("Should send error response");

    assert_eq!(error_frame.header.opcode_enum(), Some(Opcode::Error));
}

/// Test that KeyPackage is consumed after fetch (one-time use).
#[test]
fn keypackage_consumed_after_fetch() {
    let mut driver = create_driver();

    let session_a = 1001;
    let session_b = 1002;
    let user_id_b = 2000;

    // Setup both clients
    driver
        .process_event(ServerEvent::ConnectionAccepted { session_id: session_a })
        .expect("accept A");
    driver
        .process_event(ServerEvent::ConnectionAccepted { session_id: session_b })
        .expect("accept B");

    // Auth A
    let hello_a = Payload::Hello(lockframe_proto::payloads::session::Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(1000),
        auth_token: None,
    });
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: session_a,
            frame: hello_a.into_frame(FrameHeader::new(Opcode::Hello)).unwrap(),
        })
        .expect("auth A");

    // Auth B
    let hello_b = Payload::Hello(lockframe_proto::payloads::session::Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(user_id_b),
        auth_token: None,
    });
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: session_b,
            frame: hello_b.into_frame(FrameHeader::new(Opcode::Hello)).unwrap(),
        })
        .expect("auth B");

    // B publishes KeyPackage
    let publish = Payload::KeyPackagePublish(KeyPackagePublishRequest {
        key_package_bytes: vec![1, 2, 3],
        hash_ref: vec![4, 5],
    });
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: session_b,
            frame: publish.into_frame(FrameHeader::new(Opcode::KeyPackagePublish)).unwrap(),
        })
        .expect("publish");

    // First fetch should succeed
    let fetch = Payload::KeyPackageFetch(KeyPackageFetchPayload {
        user_id: user_id_b,
        key_package_bytes: vec![],
        hash_ref: vec![],
    });
    let actions = driver
        .process_event(ServerEvent::FrameReceived {
            session_id: session_a,
            frame: fetch.into_frame(FrameHeader::new(Opcode::KeyPackageFetch)).unwrap(),
        })
        .expect("first fetch");

    let first_response = actions
        .iter()
        .find_map(|a| match a {
            ServerAction::SendToSession { frame, .. } => Some(frame),
            _ => None,
        })
        .expect("first response");
    assert_eq!(first_response.header.opcode_enum(), Some(Opcode::KeyPackageFetch));

    // Second fetch should fail (consumed)
    let fetch2 = Payload::KeyPackageFetch(KeyPackageFetchPayload {
        user_id: user_id_b,
        key_package_bytes: vec![],
        hash_ref: vec![],
    });
    let actions2 = driver
        .process_event(ServerEvent::FrameReceived {
            session_id: session_a,
            frame: fetch2.into_frame(FrameHeader::new(Opcode::KeyPackageFetch)).unwrap(),
        })
        .expect("second fetch");

    let second_response = actions2
        .iter()
        .find_map(|a| match a {
            ServerAction::SendToSession { frame, .. } => Some(frame),
            _ => None,
        })
        .expect("second response");

    // Second fetch should return error
    assert_eq!(
        second_response.header.opcode_enum(),
        Some(Opcode::Error),
        "Second fetch should return error (KeyPackage consumed)"
    );
}
