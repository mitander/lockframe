//! Snapshot tests for wire format stability.
//!
//! These tests use insta to create binary snapshots of all frame types.
//! If the wire format changes, these tests will fail, ensuring we don't
//! accidentally break protocol compatibility.

use insta::assert_snapshot;
use sunder_proto::{
    Frame, FrameHeader, Opcode, Payload,
    payloads::{
        ErrorPayload,
        app::{EncryptedMessage, Reaction, Receipt, ReceiptType},
        mls::{CommitData, KeyPackageData, ProposalData, WelcomeData},
        moderation::{Ban, Kick, Redact},
        session::{Goodbye, Hello, HelloReply},
    },
};

/// Helper to encode frame to hex string for snapshot
fn frame_to_hex(frame: &Frame) -> String {
    let mut buf = Vec::new();
    frame.encode(&mut buf).expect("encoding should succeed");
    hex::encode(&buf)
}

// =============================================================================
// Session Management Frames
// =============================================================================

#[test]
fn snapshot_hello_frame() {
    let hello = Payload::Hello(Hello { version: 1, capabilities: vec![], auth_token: None });

    let frame =
        hello.into_frame(FrameHeader::new(Opcode::Hello)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_hello_frame_with_capabilities() {
    let hello = Payload::Hello(Hello {
        version: 1,
        capabilities: vec!["mls".to_string(), "e2ee".to_string()],
        auth_token: None,
    });

    let frame =
        hello.into_frame(FrameHeader::new(Opcode::Hello)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_hello_frame_with_auth_token() {
    let hello = Payload::Hello(Hello {
        version: 1,
        capabilities: vec![],
        auth_token: Some(vec![0xde, 0xad, 0xbe, 0xef]),
    });

    let frame =
        hello.into_frame(FrameHeader::new(Opcode::Hello)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_hello_reply_frame() {
    let reply = Payload::HelloReply(HelloReply {
        session_id: 0x1000_0000_0000_0000,
        capabilities: vec![],
        challenge: None,
    });

    let frame = reply
        .into_frame(FrameHeader::new(Opcode::HelloReply))
        .expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_hello_reply_frame_with_challenge() {
    let reply = Payload::HelloReply(HelloReply {
        session_id: 0x1000_0000_0000_0000,
        capabilities: vec!["mls".to_string()],
        challenge: Some(vec![0x01, 0x02, 0x03, 0x04]),
    });

    let frame = reply
        .into_frame(FrameHeader::new(Opcode::HelloReply))
        .expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_goodbye_frame() {
    let goodbye = Payload::Goodbye(Goodbye { reason: "client shutdown".to_string() });

    let frame = goodbye
        .into_frame(FrameHeader::new(Opcode::Goodbye))
        .expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_ping_frame() {
    let ping_header = FrameHeader::new(Opcode::Ping);
    let frame = Frame::new(ping_header, Vec::new());

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_pong_frame() {
    let pong_header = FrameHeader::new(Opcode::Pong);
    let frame = Frame::new(pong_header, Vec::new());

    assert_snapshot!(frame_to_hex(&frame));
}

// =============================================================================
// Application Message Frames
// =============================================================================

#[test]
fn snapshot_encrypted_message_frame() {
    let msg = Payload::AppMessage(EncryptedMessage {
        ciphertext: vec![0xca, 0xfe, 0xba, 0xbe],
        tag: [0x01; 16],
        nonce: [0x02; 24],
        push_keys: None,
    });

    let frame = msg
        .into_frame(FrameHeader::new(Opcode::AppMessage))
        .expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_receipt_frame() {
    let receipt = Payload::AppReceipt(Receipt {
        message_log_index: 42,
        kind: ReceiptType::Read,
        timestamp: 1234567890,
    });

    let frame = receipt
        .into_frame(FrameHeader::new(Opcode::AppReceipt))
        .expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_reaction_frame() {
    let reaction = Payload::AppReaction(Reaction {
        message_log_index: 100,
        content: "👍".to_string(),
        add: true,
    });

    let frame = reaction
        .into_frame(FrameHeader::new(Opcode::AppReaction))
        .expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

// =============================================================================
// MLS Operation Frames
// =============================================================================

#[test]
fn snapshot_key_package_frame() {
    let kp =
        Payload::KeyPackage(KeyPackageData { key_package_bytes: vec![0x01, 0x02, 0x03, 0x04] });

    let frame =
        kp.into_frame(FrameHeader::new(Opcode::KeyPackage)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_proposal_frame() {
    let proposal = Payload::Proposal(ProposalData {
        proposal_bytes: vec![0x05, 0x06, 0x07, 0x08],
        proposal_type: sunder_proto::payloads::mls::ProposalType::Add,
    });

    let frame = proposal
        .into_frame(FrameHeader::new(Opcode::Proposal))
        .expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_commit_frame() {
    let commit = Payload::Commit(CommitData {
        commit_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        new_epoch: 100,
        tree_hash: [0xab; 32],
        is_external: false,
    });

    let frame =
        commit.into_frame(FrameHeader::new(Opcode::Commit)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_welcome_frame() {
    let welcome =
        Payload::Welcome(WelcomeData { welcome_bytes: vec![0xaa, 0xbb, 0xcc, 0xdd], epoch: 42 });

    let frame = welcome
        .into_frame(FrameHeader::new(Opcode::Welcome))
        .expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

// =============================================================================
// Moderation Frames
// =============================================================================

#[test]
fn snapshot_redact_frame() {
    let redact = Payload::Redact(Redact {
        message_log_index: 999,
        reason: "spam".to_string(),
        moderator_id: 1,
    });

    let frame =
        redact.into_frame(FrameHeader::new(Opcode::Redact)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_ban_frame() {
    let ban = Payload::Ban(Ban {
        user_id: 0x5000_0000_0000_0001,
        reason: "policy violation".to_string(),
        duration_secs: Some(86400), // 24 hours
        moderator_id: 1,
    });

    let frame =
        ban.into_frame(FrameHeader::new(Opcode::Ban)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_ban_frame_permanent() {
    let ban = Payload::Ban(Ban {
        user_id: 0x5000_0000_0000_0002,
        reason: "terms of service violation".to_string(),
        duration_secs: None, // Permanent ban
        moderator_id: 1,
    });

    let frame =
        ban.into_frame(FrameHeader::new(Opcode::Ban)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_kick_frame() {
    let kick = Payload::Kick(Kick {
        user_id: 0x6000_0000_0000_0001,
        reason: "disruptive behavior".to_string(),
        moderator_id: 1,
    });

    let frame =
        kick.into_frame(FrameHeader::new(Opcode::Kick)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

// =============================================================================
// Error Frames
// =============================================================================

#[test]
fn snapshot_error_frame() {
    let error = Payload::Error(ErrorPayload {
        code: 400,
        message: "Invalid request".to_string(),
        retry_after: None,
    });

    let frame =
        error.into_frame(FrameHeader::new(Opcode::Error)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}

#[test]
fn snapshot_error_frame_with_retry() {
    let error = Payload::Error(ErrorPayload {
        code: 429,
        message: "Rate limit exceeded".to_string(),
        retry_after: Some(60),
    });

    let frame =
        error.into_frame(FrameHeader::new(Opcode::Error)).expect("frame creation should succeed");

    assert_snapshot!(frame_to_hex(&frame));
}
