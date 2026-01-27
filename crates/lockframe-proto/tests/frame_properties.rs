//! Property-based tests for Frame encoding/decoding
//!
//! These tests verify that frame serialization is correct for ALL valid inputs,
//! not just specific examples. Uses proptest to generate arbitrary frames and
//! verify round-trip properties.

use bytes::Bytes;
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

/// Strategy for generating arbitrary frame headers
fn arbitrary_header() -> impl Strategy<Value = FrameHeader> {
    (
        arbitrary_opcode(),
        any::<u128>(), // room_id
        any::<u64>(),  // sender_id
        any::<u64>(),  // epoch
        any::<u64>(),  // context_id (log_index or recipient_id depending on opcode)
    )
        .prop_map(|(opcode, room_id, sender_id, epoch, context_id)| {
            let mut header = FrameHeader::new(opcode);
            header.set_room_id(room_id);
            header.set_sender_id(sender_id);
            header.set_epoch(epoch);
            if opcode == Opcode::Welcome {
                header.set_recipient_id(context_id);
            } else {
                header.set_log_index(context_id);
            }
            header
        })
}

/// Strategy for generating arbitrary frames with payloads
fn arbitrary_frame() -> impl Strategy<Value = Frame> {
    (
        arbitrary_header(),
        prop::collection::vec(any::<u8>(), 0..1024), // payload up to 1KB
    )
        .prop_map(|(header, payload)| Frame::new(header, Bytes::from(payload)))
}

#[test]
fn prop_frame_encode_decode_roundtrip() {
    proptest!(|(frame in arbitrary_frame())| {
        // Encode frame to bytes
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode should succeed");

        // Decode bytes back to frame
        let decoded = Frame::decode(&buf).expect("decode should succeed");

        // PROPERTY: Round-trip must be identity
        prop_assert_eq!(decoded.header, frame.header, "Header mismatch after round-trip");
        prop_assert_eq!(
            decoded.payload.len(),
            frame.payload.len(),
            "Payload length mismatch"
        );
        prop_assert_eq!(decoded.payload, frame.payload, "Payload content mismatch");
    });
}

#[test]
fn prop_frame_header_roundtrip() {
    proptest!(|(header in arbitrary_header())| {
        // Convert header to bytes
        let bytes = header.to_bytes();

        // Parse bytes back to header
        let decoded = FrameHeader::from_bytes(&bytes).expect("from_bytes should succeed");

        // PROPERTY: Header round-trip must be identity
        prop_assert_eq!(decoded.opcode(), header.opcode(), "Opcode mismatch");
        prop_assert_eq!(decoded.room_id(), header.room_id(), "Room ID mismatch");
        prop_assert_eq!(decoded.sender_id(), header.sender_id(), "Sender ID mismatch");
        prop_assert_eq!(decoded.epoch(), header.epoch(), "Epoch mismatch");
        // Use correct getter based on opcode (context_id has different semantics)
        if header.opcode_enum() == Some(Opcode::Welcome) {
            prop_assert_eq!(decoded.recipient_id(), header.recipient_id(), "Recipient ID mismatch");
        } else {
            prop_assert_eq!(decoded.log_index(), header.log_index(), "Log index mismatch");
        }
        prop_assert_eq!(
            decoded.payload_size(),
            header.payload_size(),
            "Payload size mismatch"
        );
    });
}

#[test]
fn prop_frame_empty_payload() {
    proptest!(|(header in arbitrary_header())| {
        // Create frame with empty payload
        let frame = Frame::new(header, Bytes::new());

        // Encode and decode
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode should succeed");

        let decoded = Frame::decode(&buf).expect("decode should succeed");

        // PROPERTY: Empty payload preserved
        prop_assert_eq!(decoded.payload.len(), 0, "Empty payload should remain empty");
        prop_assert_eq!(decoded.header.payload_size(), 0, "Header should show 0 payload");
    });
}

#[test]
fn prop_frame_max_payload() {
    proptest!(|(
        header in arbitrary_header(),
        // Use smaller max for performance (full 16MB takes too long)
        payload in prop::collection::vec(any::<u8>(), 1024..2048),
    )| {
        let frame = Frame::new(header, Bytes::from(payload.clone()));

        // Encode and decode
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode should succeed");

        let decoded = Frame::decode(&buf).expect("decode should succeed");

        // PROPERTY: Large payloads preserved exactly
        prop_assert_eq!(decoded.payload.len(), payload.len(), "Payload length mismatch");
        prop_assert_eq!(&decoded.payload[..], &payload[..], "Payload content mismatch");
    });
}

#[test]
fn prop_frame_opcode_preservation() {
    proptest!(|(opcode in arbitrary_opcode())| {
        let mut header = FrameHeader::new(opcode);
        header.set_room_id(1);

        let frame = Frame::new(header, Bytes::new());

        // Encode and decode
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode should succeed");

        let decoded = Frame::decode(&buf).expect("decode should succeed");

        // PROPERTY: Opcode must be preserved exactly
        prop_assert_eq!(
            decoded.header.opcode_enum(),
            Some(opcode),
            "Opcode not preserved: expected {:?}, got {:?}",
            opcode,
            decoded.header.opcode_enum()
        );
    });
}

#[test]
fn prop_frame_ids_preserved() {
    proptest!(|(
        room_id in any::<u128>(),
        sender_id in any::<u64>(),
        epoch in any::<u64>(),
        log_index in any::<u64>(),
    )| {
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(sender_id);
        header.set_epoch(epoch);
        header.set_log_index(log_index);

        let frame = Frame::new(header, Bytes::from(vec![42u8; 16]));

        // Encode and decode
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode should succeed");

        let decoded = Frame::decode(&buf).expect("decode should succeed");

        // PROPERTY: All IDs must be preserved exactly
        prop_assert_eq!(decoded.header.room_id(), room_id, "Room ID mismatch");
        prop_assert_eq!(decoded.header.sender_id(), sender_id, "Sender ID mismatch");
        prop_assert_eq!(decoded.header.epoch(), epoch, "Epoch mismatch");
        prop_assert_eq!(decoded.header.log_index(), log_index, "Log index mismatch");
    });
}

#[test]
fn prop_frame_encoded_size_correct() {
    proptest!(|(frame in arbitrary_frame())| {
        // Encode frame
        let mut buf = Vec::new();
        frame.encode(&mut buf).expect("encode should succeed");

        // PROPERTY: Encoded size must equal header size + payload size
        #[allow(clippy::arithmetic_side_effects)] // Test code: values bounded by property test
        let expected_size = FrameHeader::SIZE + frame.payload.len();
        prop_assert_eq!(
            buf.len(),
            expected_size,
            "Encoded size mismatch: expected {}, got {}",
            expected_size,
            buf.len()
        );
    });
}
