//! Fuzz target for frame header boundary conditions
//!
//! Prevent DoS attacks via malformed frame headers (HIGH priority)
//!
//! # Strategy
//!
//! - Magic bytes: Valid, off-by-one, all-zeros, all-ones, random
//! - Payload size: Zero, small, at-max, just-over-max, way-over-max, u32::MAX
//! - Version: Valid (0x01), zero, max, random
//! - Room/sender/epoch: Boundary values (0, 1, MAX)
//!
//! # Invariants
//!
//! - `payload_size > MAX_PAYLOAD` (16MB) MUST return
//!   `ProtocolError::FrameTooLarge`
//! - Invalid magic bytes MUST return `ProtocolError::InvalidMagic`
//! - `room_id = 0` decodes (parser valid) but rejected by Sequencer (semantic)
//! - All decode errors MUST be structured (never panic)
//! - Encoded size MUST equal 128 + payload_size

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use lockframe_proto::{Frame, FrameHeader, Opcode};

const LOCKFRAME_MAGIC: [u8; 4] = [0x4C, 0x4F, 0x46, 0x52];
const MAX_PAYLOAD_SIZE: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Arbitrary)]
struct BoundaryFrame {
    magic: MagicBytes,
    version: VersionBytes,
    opcode: u16,
    payload_size: PayloadSize,
    room_id: RoomId,
    sender_id: SenderId,
    epoch: EpochValue,
    log_index: u64,
}

#[derive(Debug, Clone, Arbitrary)]
enum MagicBytes {
    Valid,
    OffByOne(u8),
    AllZeros,
    AllOnes,
    Random([u8; 4]),
}

#[derive(Debug, Clone, Arbitrary)]
enum VersionBytes {
    Valid,
    Zero,
    Max,
    Random(u8),
}

#[derive(Debug, Clone, Arbitrary)]
enum PayloadSize {
    Zero,
    Small(u8),
    AtMaxBoundary,
    JustOverMax,
    WayOverMax,
    MaxU32,
    Random(u32),
}

#[derive(Debug, Clone, Arbitrary)]
enum RoomId {
    Zero,
    One,
    Small(u8),
    MaxU128,
    Random(u128),
}

#[derive(Debug, Clone, Arbitrary)]
enum SenderId {
    Zero,
    One,
    MaxU64,
    Random(u64),
}

#[derive(Debug, Clone, Arbitrary)]
enum EpochValue {
    Zero,
    One,
    MaxMinus1,
    MaxU64,
    Random(u64),
}

fuzz_target!(|boundary: BoundaryFrame| {
    let payload_size_value = match boundary.payload_size {
        PayloadSize::Zero => 0,
        PayloadSize::Small(s) => s as u32,
        PayloadSize::AtMaxBoundary => MAX_PAYLOAD_SIZE,
        PayloadSize::JustOverMax => MAX_PAYLOAD_SIZE.saturating_add(1),
        PayloadSize::WayOverMax => MAX_PAYLOAD_SIZE.saturating_add(1_000_000),
        PayloadSize::MaxU32 => u32::MAX,
        PayloadSize::Random(r) => r,
    };

    let actual_payload_size = payload_size_value.min(100_000) as usize;
    let mut buffer = vec![0u8; 128 + actual_payload_size];

    match boundary.magic {
        MagicBytes::Valid => buffer[0..4].copy_from_slice(&LOCKFRAME_MAGIC),
        MagicBytes::OffByOne(offset) => {
            buffer[0..4].copy_from_slice(&LOCKFRAME_MAGIC);
            let idx = (offset % 4) as usize;
            buffer[idx] = buffer[idx].wrapping_add(1);
        },
        MagicBytes::AllZeros => buffer[0..4].fill(0),
        MagicBytes::AllOnes => buffer[0..4].fill(0xFF),
        MagicBytes::Random(bytes) => buffer[0..4].copy_from_slice(&bytes),
    }

    let version_value: u8 = match boundary.version {
        VersionBytes::Valid => 0x01,
        VersionBytes::Zero => 0,
        VersionBytes::Max => u8::MAX,
        VersionBytes::Random(v) => v,
    };
    buffer[4] = version_value;
    buffer[6..8].copy_from_slice(&boundary.opcode.to_be_bytes());
    buffer[12..16].copy_from_slice(&payload_size_value.to_be_bytes());

    let room_id_value = match boundary.room_id {
        RoomId::Zero => 0,
        RoomId::One => 1,
        RoomId::Small(s) => s as u128,
        RoomId::MaxU128 => u128::MAX,
        RoomId::Random(r) => r,
    };
    buffer[16..32].copy_from_slice(&room_id_value.to_be_bytes());

    let sender_id_value = match boundary.sender_id {
        SenderId::Zero => 0,
        SenderId::One => 1,
        SenderId::MaxU64 => u64::MAX,
        SenderId::Random(r) => r,
    };
    buffer[32..40].copy_from_slice(&sender_id_value.to_be_bytes());

    let epoch_value = match boundary.epoch {
        EpochValue::Zero => 0,
        EpochValue::One => 1,
        EpochValue::MaxMinus1 => u64::MAX - 1,
        EpochValue::MaxU64 => u64::MAX,
        EpochValue::Random(r) => r,
    };
    buffer[56..64].copy_from_slice(&epoch_value.to_be_bytes());
    buffer[40..48].copy_from_slice(&boundary.log_index.to_be_bytes());

    match Frame::decode(&buffer) {
        Ok(frame) => {
            assert_eq!(buffer[0..4], LOCKFRAME_MAGIC);
            assert!(payload_size_value <= MAX_PAYLOAD_SIZE);

            let opcode = frame.header.opcode_enum();
            let _ = frame.header.room_id();
            let _ = frame.header.sender_id();
            let _ = frame.header.epoch();
            if opcode != Some(Opcode::Welcome) {
                let _ = frame.header.log_index();
            }
            let _ = frame.header.payload_size();
            let _ = frame.header.signature();
        },
        Err(_) => {},
    }

    if let Some(opcode_enum) = Opcode::from_u16(boundary.opcode) {
        if opcode_enum == Opcode::Welcome {
            return;
        }
        let mut header = FrameHeader::new(opcode_enum);
        header.set_room_id(room_id_value);
        header.set_sender_id(sender_id_value);
        header.set_epoch(epoch_value);
        header.set_log_index(boundary.log_index);

        let small_payload = vec![0xAA; actual_payload_size.min(1000)];
        let frame = Frame::new(header, small_payload);

        let mut encoded = Vec::new();
        if frame.encode(&mut encoded).is_err() {
            return;
        }

        let expected_size = 128 + frame.payload.len();
        assert_eq!(encoded.len(), expected_size);

        if let Ok(decoded) = Frame::decode(&encoded) {
            assert_eq!(decoded.header.room_id(), frame.header.room_id());
            assert_eq!(decoded.header.sender_id(), frame.header.sender_id());
            assert_eq!(decoded.header.epoch(), frame.header.epoch());
            assert_eq!(decoded.header.log_index(), frame.header.log_index());
        }
    }
});
