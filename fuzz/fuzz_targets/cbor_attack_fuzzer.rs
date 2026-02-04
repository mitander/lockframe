//! Fuzz target for CBOR deserialization attacks
//!
//! Harden CBOR payload deserialization against attacks (MEDIUM priority)
//!
//! # Strategy
//!
//! - Deeply nested: Arrays/maps nested to arbitrary depth (stack overflow)
//! - Huge lengths: CBOR claiming massive byte/string/array lengths (memory)
//! - Random bytes: Completely arbitrary CBOR data (general malformation)
//! - Type confusion: Payload bytes that don't match frame opcode
//! - Duplicate keys: CBOR maps with repeated key names
//!
//! # Invariants
//!
//! - Deserialization completes quickly (no infinite loops)
//! - Deeply nested structures handled gracefully
//! - Huge claimed lengths rejected (not allocated)
//! - Type confusion (wrong payload for opcode) returns error
//! - NEVER panic on malformed CBOR

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lockframe_proto::{Frame, FrameHeader, Opcode, Payload};

#[derive(Debug, Clone, Arbitrary)]
enum CborAttack {
    DeeplyNested { depth: u8, payload_type: PayloadType },
    HugeLength { claimed_len_exponent: u8 },
    RandomBytes { bytes: Vec<u8> },
    TypeConfusion { opcode: u16, wrong_payload_bytes: Vec<u8> },
    DuplicateKeys { count: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
enum PayloadType {
    Array,
    Map,
    Bytes,
    String,
}

fuzz_target!(|attack: CborAttack| {
    match attack {
        CborAttack::DeeplyNested { depth, payload_type } => {
            let actual_depth = (depth % 50) as usize;
            let cbor_bytes = create_nested_cbor(actual_depth, &payload_type);

            for opcode in [Opcode::Hello, Opcode::AppMessage, Opcode::Commit, Opcode::Welcome] {
                let frame = Frame::new(FrameHeader::new(opcode), cbor_bytes.clone());
                let _ = Payload::from_frame(&frame);
            }
        }

        CborAttack::HugeLength { claimed_len_exponent } => {
            let exponent = (claimed_len_exponent % 21) as u32;
            let claimed_length = if exponent < 20 {
                1u32 << exponent
            } else {
                u32::MAX
            };

            let attacks = [
                create_huge_byte_string(claimed_length),
                create_huge_text_string(claimed_length),
                create_huge_array(claimed_length),
            ];

            for cbor_bytes in attacks {
                for opcode in [Opcode::Proposal, Opcode::Commit, Opcode::Ban, Opcode::Hello] {
                    let frame = Frame::new(FrameHeader::new(opcode), cbor_bytes.clone());
                    let _ = Payload::from_frame(&frame);
                }
            }
        }

        CborAttack::RandomBytes { bytes } => {
            let opcodes = [
                Opcode::Hello,
                Opcode::HelloReply,
                Opcode::Ping,
                Opcode::Pong,
                Opcode::Goodbye,
                Opcode::Error,
                Opcode::AppMessage,
                Opcode::KeyPackage,
                Opcode::Proposal,
                Opcode::Commit,
                Opcode::Welcome,
                Opcode::Redact,
                Opcode::Ban,
                Opcode::Kick,
            ];

            for opcode in opcodes {
                let frame = Frame::new(FrameHeader::new(opcode), bytes.clone());
                let _ = Payload::from_frame(&frame);
            }
        }

        CborAttack::TypeConfusion { opcode, wrong_payload_bytes } => {
            let opcode_enum = Opcode::from_u16(opcode).unwrap_or(Opcode::AppMessage);
            let frame = Frame::new(FrameHeader::new(opcode_enum), wrong_payload_bytes);
            let _ = Payload::from_frame(&frame);
        }

        CborAttack::DuplicateKeys { count } => {
            let actual_count = (count % 10).max(2);
            let mut cbor_bytes = vec![0xA0 | actual_count];

            for _ in 0..actual_count {
                cbor_bytes.push(0x67);
                cbor_bytes.extend_from_slice(b"version");
                cbor_bytes.push(0x01);
            }

            let frame = Frame::new(FrameHeader::new(Opcode::Hello), cbor_bytes);
            let _ = Payload::from_frame(&frame);
        }
    }
});

fn create_nested_cbor(depth: usize, payload_type: &PayloadType) -> Vec<u8> {
    let mut bytes = Vec::new();

    match payload_type {
        PayloadType::Array => {
            for _ in 0..depth {
                bytes.push(0x81);
            }
            bytes.push(0x01);
        }
        PayloadType::Map => {
            for _ in 0..depth {
                bytes.push(0xA1);
                bytes.push(0x61);
                bytes.push(b'a');
            }
            bytes.push(0x01);
        }
        PayloadType::Bytes => {
            for _ in 0..depth {
                bytes.push(0x81);
            }
            bytes.push(0x41);
            bytes.push(0x00);
        }
        PayloadType::String => {
            for _ in 0..depth {
                bytes.push(0x81);
            }
            bytes.push(0x61);
            bytes.push(b'x');
        }
    }

    bytes
}

fn create_huge_byte_string(claimed_length: u32) -> Vec<u8> {
    let mut bytes = vec![0x5A];
    bytes.extend_from_slice(&claimed_length.to_be_bytes());
    bytes.extend(vec![0xAA; (claimed_length as usize).min(10)]);
    bytes
}

fn create_huge_text_string(claimed_length: u32) -> Vec<u8> {
    let mut bytes = vec![0x7A];
    bytes.extend_from_slice(&claimed_length.to_be_bytes());
    bytes.extend(vec![b'x'; (claimed_length as usize).min(10)]);
    bytes
}

fn create_huge_array(claimed_length: u32) -> Vec<u8> {
    let mut bytes = vec![0x9A];
    bytes.extend_from_slice(&claimed_length.to_be_bytes());
    for _ in 0..(claimed_length as usize).min(5) {
        bytes.push(0x01);
    }
    bytes
}
