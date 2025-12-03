//! Fuzz target for Sequencer with invalid/malicious frames
//!
//! This fuzzer tests sequencer robustness with:
//! - Invalid frame headers (wrong magic, version)
//! - Epoch manipulation (wrong epoch, overflow attempts)
//! - Room ID edge cases (zero, MAX)
//! - Log index manipulation
//! - Malformed payloads
//!
//! The sequencer should handle all invalid inputs gracefully, either:
//! - Rejecting with ValidationResult::Reject
//! - Returning a structured error
//! - Never panicking

#![no_main]

use libfuzzer_sys::fuzz_target;
use kalandra_core::{
    sequencer::Sequencer,
    storage::MemoryStorage,
    mls::MlsValidator,
};
use kalandra_proto::{Frame, FrameHeader, Opcode};
use bytes::Bytes;

fuzz_target!(|data: &[u8]| {
    if data.len() < 128 {
        return; // Need at least a header
    }

    let storage = MemoryStorage::new();
    let validator = MlsValidator;
    let mut sequencer = Sequencer::new();

    // Try to create a frame from the fuzzed data
    let result = Frame::decode(data);

    if let Ok(frame) = result {
        // Attempt to process the frame through the sequencer
        // This should never panic, even with completely invalid frames
        let _ = sequencer.process_frame(frame, &storage, &validator);
    }

    // Also test with specific malicious patterns
    if data.len() >= 16 {
        // Extract some values from fuzz data
        let room_id = u128::from_be_bytes(data[0..16].try_into().unwrap_or([0u8; 16]));
        let epoch = if data.len() >= 24 {
            u64::from_be_bytes(data[16..24].try_into().unwrap_or([0u8; 8]))
        } else {
            0
        };

        // Create frame with potentially malicious header values
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_epoch(epoch);
        header.set_sender_id(1);
        header.set_log_index(0);

        let payload_data = if data.len() > 24 { &data[24..] } else { &[] };
        let frame = Frame::new(header, Bytes::copy_from_slice(payload_data));

        let _ = sequencer.process_frame(frame, &storage, &validator);
    }
});
