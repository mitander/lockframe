//! Fuzz target for Frame::decode
//!
//! This fuzzer tests frame decoding with arbitrary byte sequences to find:
//! - Parser crashes or panics
//! - Integer overflows in size calculations
//! - Buffer over-reads
//! - Malformed headers that bypass validation
//!
//! The fuzzer should NEVER panic. All invalid inputs should return an error.

#![no_main]

use libfuzzer_sys::fuzz_target;
use kalandra_proto::Frame;

fuzz_target!(|data: &[u8]| {
    // Attempt to decode arbitrary bytes as a frame
    // This should never panic, only return Err for invalid data
    let _ = Frame::decode(data);
});
