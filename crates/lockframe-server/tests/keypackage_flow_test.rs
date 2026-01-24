//! Integration tests for KeyPackage publish/fetch flow.
//!
//! Tests the complete multi-client join flow:
//! 1. Client B publishes KeyPackage to server
//! 2. Client A fetches KeyPackage for user_id B
//! 3. Server routes Welcome to B after A adds them

use std::time::Duration;

use bytes::Bytes;
use lockframe_core::env::Environment;
use lockframe_proto::{
    Frame, FrameHeader, Opcode, Payload,
    payloads::mls::{KeyPackageFetchPayload, KeyPackagePublishRequest},
};
use lockframe_server::{DriverConfig, MemoryStorage, ServerAction, ServerDriver, ServerEvent};

// Test environment using system time and RNG
#[derive(Clone)]
struct TestEnv;

impl Environment for TestEnv {
    type Instant = std::time::Instant;

    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send {
        async move {
            tokio::time::sleep(duration).await;
        }
    }

    fn random_bytes(&self, buffer: &mut [u8]) {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buffer);
    }
}

fn create_driver() -> ServerDriver<TestEnv, MemoryStorage> {
    let env = TestEnv;
    let storage = MemoryStorage::new();
    let config = DriverConfig::default();
    ServerDriver::new(env, storage, config)
}

/// Test that Client B can publish a KeyPackage and Client A can fetch it.
#[test]
fn keypackage_publish_and_fetch_flow() {
    let mut driver = create_driver();

    let client_a_session = 1001;
    let client_b_session = 1002;
    let user_id_b = 2000;

    // Connect both clients
    driver
        .process_event(ServerEvent::ConnectionAccepted { session_id: client_a_session })
        .expect("accept A");
    driver
        .process_event(ServerEvent::ConnectionAccepted { session_id: client_b_session })
        .expect("accept B");

    // Authenticate Client A
    let hello_a = Payload::Hello(lockframe_proto::payloads::session::Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(1000), // Client A's user_id
        auth_token: None,
    });
    let hello_frame_a =
        hello_a.into_frame(FrameHeader::new(Opcode::Hello)).expect("create hello frame");
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: client_a_session,
            frame: hello_frame_a,
        })
        .expect("auth A");

    // Authenticate Client B with specific user_id
    let hello_b = Payload::Hello(lockframe_proto::payloads::session::Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(user_id_b),
        auth_token: None,
    });
    let hello_frame_b =
        hello_b.into_frame(FrameHeader::new(Opcode::Hello)).expect("create hello frame");
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: client_b_session,
            frame: hello_frame_b,
        })
        .expect("auth B");

    // Client B publishes KeyPackage
    let kp_bytes = vec![0x01, 0x02, 0x03, 0x04]; // Fake KeyPackage bytes
    let hash_ref = vec![0xaa, 0xbb, 0xcc];
    let publish_payload = Payload::KeyPackagePublish(KeyPackagePublishRequest {
        key_package_bytes: kp_bytes.clone(),
        hash_ref: hash_ref.clone(),
    });
    let publish_frame = publish_payload
        .into_frame(FrameHeader::new(Opcode::KeyPackagePublish))
        .expect("create publish frame");

    let publish_actions = driver
        .process_event(ServerEvent::FrameReceived {
            session_id: client_b_session,
            frame: publish_frame,
        })
        .expect("publish KeyPackage");

    // Should log success
    assert!(
        publish_actions.iter().any(|a| matches!(a, ServerAction::Log { message, .. } if message.contains("KeyPackage published"))),
        "Should log KeyPackage publish: {:?}",
        publish_actions
    );

    // Client A fetches KeyPackage for user_id_b
    let fetch_payload = Payload::KeyPackageFetch(KeyPackageFetchPayload {
        user_id: user_id_b,
        key_package_bytes: vec![], // Empty in request
        hash_ref: vec![],
    });
    let fetch_frame = fetch_payload
        .into_frame(FrameHeader::new(Opcode::KeyPackageFetch))
        .expect("create fetch frame");

    let fetch_actions = driver
        .process_event(ServerEvent::FrameReceived {
            session_id: client_a_session,
            frame: fetch_frame,
        })
        .expect("fetch KeyPackage");

    // Should send response frame to Client A
    let response_frame = fetch_actions
        .iter()
        .find_map(|a| match a {
            ServerAction::SendToSession { session_id, frame }
                if *session_id == client_a_session =>
            {
                Some(frame)
            },
            _ => None,
        })
        .expect("Should send response to Client A");

    // Verify response contains the KeyPackage
    assert_eq!(response_frame.header.opcode_enum(), Some(Opcode::KeyPackageFetch));

    let response_payload = Payload::from_frame(response_frame.clone()).expect("decode response");
    match response_payload {
        Payload::KeyPackageFetch(kp) => {
            assert_eq!(kp.user_id, user_id_b);
            assert_eq!(kp.key_package_bytes, kp_bytes);
            assert_eq!(kp.hash_ref, hash_ref);
        },
        _ => panic!("Expected KeyPackageFetch response"),
    }
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

/// Test the full flow: create room, publish, fetch, add, welcome routing.
#[test]
fn full_multi_client_join_flow() {
    let mut driver = create_driver();

    let alice_session = 1001;
    let bob_session = 1002;
    let alice_id = 1000;
    let bob_id = 2000;
    let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;

    // Connect both
    driver.process_event(ServerEvent::ConnectionAccepted { session_id: alice_session }).unwrap();
    driver.process_event(ServerEvent::ConnectionAccepted { session_id: bob_session }).unwrap();

    // Auth Alice
    let hello_alice = Payload::Hello(lockframe_proto::payloads::session::Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(alice_id),
        auth_token: None,
    });
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: alice_session,
            frame: hello_alice.into_frame(FrameHeader::new(Opcode::Hello)).unwrap(),
        })
        .unwrap();

    // Auth Bob
    let hello_bob = Payload::Hello(lockframe_proto::payloads::session::Hello {
        version: 1,
        capabilities: vec![],
        sender_id: Some(bob_id),
        auth_token: None,
    });
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: bob_session,
            frame: hello_bob.into_frame(FrameHeader::new(Opcode::Hello)).unwrap(),
        })
        .unwrap();

    // Bob publishes KeyPackage
    let bob_kp = Payload::KeyPackagePublish(KeyPackagePublishRequest {
        key_package_bytes: vec![0xb0, 0xb0, 0xb0],
        hash_ref: vec![0xbb],
    });
    driver
        .process_event(ServerEvent::FrameReceived {
            session_id: bob_session,
            frame: bob_kp.into_frame(FrameHeader::new(Opcode::KeyPackagePublish)).unwrap(),
        })
        .unwrap();

    // Alice fetches Bob's KeyPackage
    let fetch_bob = Payload::KeyPackageFetch(KeyPackageFetchPayload {
        user_id: bob_id,
        key_package_bytes: vec![],
        hash_ref: vec![],
    });
    let fetch_actions = driver
        .process_event(ServerEvent::FrameReceived {
            session_id: alice_session,
            frame: fetch_bob.into_frame(FrameHeader::new(Opcode::KeyPackageFetch)).unwrap(),
        })
        .unwrap();

    // Verify Alice gets Bob's KeyPackage
    let kp_response = fetch_actions.iter().find_map(|a| match a {
        ServerAction::SendToSession { session_id, frame } if *session_id == alice_session => {
            Payload::from_frame(frame.clone()).ok()
        },
        _ => None,
    });

    match kp_response {
        Some(Payload::KeyPackageFetch(kp)) => {
            assert_eq!(kp.user_id, bob_id);
            assert_eq!(kp.key_package_bytes, vec![0xb0, 0xb0, 0xb0]);
        },
        _ => panic!("Expected KeyPackageFetch response"),
    }

    // Alice creates room and sends Commit (auto-creates room on server)
    let mut commit_header = FrameHeader::new(Opcode::Commit);
    commit_header.set_room_id(room_id);
    commit_header.set_sender_id(alice_id);
    commit_header.set_epoch(0);
    let commit_frame = Frame::new(commit_header, Bytes::from("commit_payload"));

    let commit_actions = driver
        .process_event(ServerEvent::FrameReceived {
            session_id: alice_session,
            frame: commit_frame,
        })
        .unwrap();

    // Should broadcast and persist
    assert!(
        commit_actions.iter().any(
            |a| matches!(a, ServerAction::BroadcastToRoom { room_id: rid, .. } if *rid == room_id)
        ),
        "Commit should be broadcast"
    );

    // Now Alice sends Welcome to Bob
    let mut welcome_header = FrameHeader::new(Opcode::Welcome);
    welcome_header.set_room_id(room_id);
    welcome_header.set_sender_id(alice_id);
    welcome_header.set_recipient_id(bob_id);
    welcome_header.set_epoch(0);
    let welcome_frame = Frame::new(welcome_header, Bytes::from("welcome_payload"));

    let welcome_actions = driver
        .process_event(ServerEvent::FrameReceived {
            session_id: alice_session,
            frame: welcome_frame,
        })
        .unwrap();

    // Welcome should be routed to Bob
    let welcome_to_bob = welcome_actions.iter().any(|a| {
        matches!(a, ServerAction::SendToSession { session_id, frame }
            if *session_id == bob_session && frame.header.opcode_enum() == Some(Opcode::Welcome))
    });

    assert!(welcome_to_bob, "Welcome should be routed to Bob: {:?}", welcome_actions);
}
