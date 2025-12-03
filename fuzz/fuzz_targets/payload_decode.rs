//! Fuzz target for Payload::from_frame
//!
//! This fuzzer tests payload deserialization (CBOR decoding) with:
//! - Malformed CBOR data
//! - Type confusion attacks (wrong payload type for opcode)
//! - Oversized strings or collections
//! - Nested structures exceeding depth limits
//!
//! The fuzzer should NEVER panic. All invalid inputs should return an error.

#![no_main]

use libfuzzer_sys::fuzz_target;
use kalandra_proto::{Frame, FrameHeader, Opcode, Payload};
use bytes::Bytes;

fuzz_target!(|data: &[u8]| {
    // We need a valid frame header to test payload decoding
    // Try all opcodes to test different payload types
    let opcodes = [
        Opcode::Hello,
        Opcode::HelloReply,
        Opcode::Ping,
        Opcode::Pong,
        Opcode::Goodbye,
        Opcode::Error,
        Opcode::AppMessage,
        Opcode::AppReceipt,
        Opcode::AppReaction,
        Opcode::Welcome,
        Opcode::Commit,
        Opcode::Proposal,
        Opcode::KeyPackage,
        Opcode::Redact,
        Opcode::Ban,
        Opcode::Kick,
    ];

    for opcode in opcodes {
        let mut header = FrameHeader::new(opcode);
        header.set_room_id(1);
        header.set_sender_id(1);
        header.set_epoch(0);
        header.set_log_index(0);

        let frame = Frame::new(header, Bytes::copy_from_slice(data));

        // Attempt to deserialize the payload
        // This should never panic, only return Err for invalid CBOR
        let _ = Payload::from_frame(frame);
    }
});
