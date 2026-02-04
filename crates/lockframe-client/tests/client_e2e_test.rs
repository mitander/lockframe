//! End-to-end client tests for byte-level and crypto properties.
//!
//! These tests verify properties that the model-based tests cannot cover:
//! - Encryption overhead bounds (byte sizes)
//! - Empty message handling (edge case)
//! - Malformed payload rejection (garbage bytes)
//! - Encryption determinism (same seed → same output, critical for DST)

use lockframe_client::{Client, ClientAction, ClientEvent, ClientIdentity};
use lockframe_harness::SimEnv;
use lockframe_proto::Frame;
use turmoil::Builder;

/// Test room ID
const ROOM_ID: u128 = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

/// Extract `SendFrame` actions
fn extract_send_frames(actions: &[ClientAction]) -> Vec<Frame> {
    actions
        .iter()
        .filter_map(|a| match a {
            ClientAction::Send(frame) => Some(frame.clone()),
            _ => None,
        })
        .collect()
}

/// Test that large messages are handled correctly.
///
/// WHY THIS TEST IS NEEDED:
/// The model tracks logical messages (content bytes) but doesn't verify:
/// - Encryption overhead is bounded (CBOR + nonce + auth tag < 500 bytes)
/// - Large messages (100KB) don't cause allocation failures
/// - Payload size grows proportionally with plaintext
///
/// If this test fails, it indicates:
/// - AEAD implementation has unexpected overhead
/// - Serialization format changed unexpectedly
/// - Memory allocation issues with large payloads
#[test]
fn client_large_message_handling() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();
        let alice = ClientIdentity::new(1);
        let mut alice_client = Client::new(env, alice);

        alice_client.handle(ClientEvent::CreateRoom { room_id: ROOM_ID }).expect("create room");

        // Send messages of various sizes
        let sizes = [1, 100, 1_000, 10_000, 100_000];

        for &size in &sizes {
            let plaintext = vec![b'X'; size];
            let actions = alice_client
                .handle(ClientEvent::SendMessage { room_id: ROOM_ID, plaintext: plaintext.clone() })
                .expect("send {size}-byte message");

            let frames = extract_send_frames(&actions);
            assert_eq!(frames.len(), 1);

            // Oracle: Encrypted payload should be larger than plaintext
            // (includes nonce, auth tag, CBOR overhead)
            assert!(
                frames[0].payload.len() > size,
                "Encrypted {size}B message should be larger than plaintext"
            );

            // Oracle: Check reasonable overhead (CBOR + nonce + tag < 500 bytes typically)
            let overhead = frames[0].payload.len() - size;
            assert!(overhead < 500, "Overhead for {size}B message is {overhead}B, expected < 500B");
        }

        Ok(())
    });

    sim.run().unwrap();
}

/// Test that empty messages are handled correctly.
///
/// WHY THIS TEST IS NEEDED:
/// The model doesn't distinguish between empty and non-empty messages.
/// At the byte level, we must verify:
/// - Empty plaintext produces non-empty ciphertext (nonce + auth tag)
/// - No special-case bugs for zero-length input
/// - AEAD correctly handles empty associated data
///
/// If this test fails, it indicates:
/// - Edge case bug in encryption path
/// - Missing padding or nonce for empty messages
#[test]
fn client_empty_message_handling() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();
        let alice = ClientIdentity::new(1);
        let mut alice_client = Client::new(env, alice);

        alice_client.handle(ClientEvent::CreateRoom { room_id: ROOM_ID }).expect("create room");

        // Send empty message
        let actions = alice_client
            .handle(ClientEvent::SendMessage { room_id: ROOM_ID, plaintext: vec![] })
            .expect("send empty message");

        let frames = extract_send_frames(&actions);
        assert_eq!(frames.len(), 1);

        // Oracle: Even empty message produces encrypted payload
        // (contains nonce, auth tag, CBOR structure)
        assert!(
            !frames[0].payload.is_empty(),
            "Empty message should produce non-empty encrypted payload"
        );

        Ok(())
    });

    sim.run().unwrap();
}

/// Test client behavior when receiving malformed encrypted payload.
///
/// WHY THIS TEST IS NEEDED:
/// The model doesn't simulate byte-level corruption. We must verify:
/// - Garbage bytes don't cause panics (graceful error handling)
/// - Invalid CBOR is rejected before decryption attempt
/// - Auth tag verification fails cleanly on corrupted data
///
/// If this test fails (panic instead of error), it indicates:
/// - Missing input validation
/// - Unchecked unwrap on deserialization
/// - AEAD implementation doesn't handle malformed input
#[test]
fn client_malformed_payload_handling() {
    let mut sim = Builder::new().build();

    sim.host("test", || async {
        let env = SimEnv::new();
        let alice_identity = ClientIdentity::new(1);
        let mut alice = Client::new(env, alice_identity);

        alice.handle(ClientEvent::CreateRoom { room_id: ROOM_ID }).expect("create room");

        // Create a frame with malformed/corrupted payload
        let mut header = lockframe_proto::FrameHeader::new(lockframe_proto::Opcode::AppMessage);
        header.set_room_id(ROOM_ID);
        header.set_sender_id(1);
        header.set_epoch(0);

        // Garbage payload that won't deserialize correctly
        let garbage_payload = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let bad_frame = lockframe_proto::Frame::new(header, garbage_payload);

        // Oracle: Client should handle gracefully (error, not panic)
        let result = alice.handle(ClientEvent::FrameReceived(bad_frame));

        // Should error, not panic
        assert!(result.is_err(), "Should reject malformed payload");

        Ok(())
    });

    sim.run().unwrap();
}

/// Oracle: Verify encryption produces deterministic output for same inputs.
///
/// WHY THIS TEST IS NEEDED:
/// Deterministic Simulation Testing (DST) requires that given the same:
/// - RNG seed
/// - Message sequence
/// - Client state
///
/// The system produces IDENTICAL outputs. This is critical because:
/// - Bug reproduction requires deterministic replays
/// - Turmoil simulation assumes deterministic behavior
/// - Flaky tests indicate non-determinism that breaks DST
///
/// If this test fails, it indicates:
/// - System time leaking into crypto operations
/// - Thread-local RNG instead of seeded RNG
/// - Non-deterministic hash iteration order
#[test]
fn client_encryption_determinism() {
    // Run the same sequence twice with same seed and verify same output.
    // This tests that given the same RNG seed, the client produces the same
    // ciphertexts (deterministic behavior required for DST).

    let mut sim = Builder::new().build();

    sim.host("test", || async {
        // First run with seed 12345
        let env1 = SimEnv::with_seed(12345);
        let alice1 = ClientIdentity::new(1);
        let mut alice_client1 = Client::new(env1, alice1);

        alice_client1.handle(ClientEvent::CreateRoom { room_id: ROOM_ID }).expect("create room 1");

        let mut payloads1 = Vec::new();
        for i in 0..3 {
            let actions = alice_client1
                .handle(ClientEvent::SendMessage {
                    room_id: ROOM_ID,
                    plaintext: format!("Message {i}").into_bytes(),
                })
                .expect("send message 1");

            let frames = extract_send_frames(&actions);
            assert_eq!(frames.len(), 1);
            payloads1.push(frames[0].payload.to_vec());
        }

        // Second run with same seed 12345 (use different room to avoid conflicts)
        let room_id_2 = ROOM_ID.wrapping_add(1);
        let env2 = SimEnv::with_seed(12345);
        let alice2 = ClientIdentity::new(1);
        let mut alice_client2 = Client::new(env2, alice2);

        alice_client2
            .handle(ClientEvent::CreateRoom { room_id: room_id_2 })
            .expect("create room 2");

        let mut payloads2 = Vec::new();
        for i in 0..3 {
            let actions = alice_client2
                .handle(ClientEvent::SendMessage {
                    room_id: room_id_2,
                    plaintext: format!("Message {i}").into_bytes(),
                })
                .expect("send message 2");

            let frames = extract_send_frames(&actions);
            payloads2.push(frames[0].payload.to_vec());
        }

        // Third run with different seed 54321
        let room_id_3 = ROOM_ID.wrapping_add(2);
        let env3 = SimEnv::with_seed(54321);
        let alice3 = ClientIdentity::new(1);
        let mut alice_client3 = Client::new(env3, alice3);

        alice_client3
            .handle(ClientEvent::CreateRoom { room_id: room_id_3 })
            .expect("create room 3");

        let mut payloads3 = Vec::new();
        for i in 0..3 {
            let actions = alice_client3
                .handle(ClientEvent::SendMessage {
                    room_id: room_id_3,
                    plaintext: format!("Message {i}").into_bytes(),
                })
                .expect("send message 3");

            let frames = extract_send_frames(&actions);
            payloads3.push(frames[0].payload.to_vec());
        }

        // Oracle: Same seed produces same ciphertexts
        assert_eq!(payloads1, payloads2, "Same seed should produce deterministic encryption");

        // Oracle: Different seed produces different ciphertexts
        assert_ne!(payloads1, payloads3, "Different seed should produce different encryption");

        Ok(())
    });

    sim.run().unwrap();
}
