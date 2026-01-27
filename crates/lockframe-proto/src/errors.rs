//! Error types for the Lockframe protocol.
//!
//! All errors are structured, testable, and provide actionable information.

use thiserror::Error;

/// Protocol-level errors that can occur during frame parsing and validation.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    // Frame parsing errors
    /// Frame is shorter than the minimum header size
    #[error("frame too short: expected at least {expected} bytes, got {actual}")]
    FrameTooShort {
        /// Expected minimum size in bytes
        expected: usize,
        /// Actual size received
        actual: usize,
    },

    /// Invalid magic number in frame header
    #[error("invalid magic number: expected 0x4C4F4652 (\"LOFR\")")]
    InvalidMagic,

    /// Unsupported protocol version
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Payload exceeds maximum allowed size
    #[error("payload too large: {size} bytes exceeds maximum {max}")]
    PayloadTooLarge {
        /// Actual payload size
        size: usize,
        /// Maximum allowed size
        max: usize,
    },

    /// Frame is truncated (header claims more data than available)
    #[error("frame truncated: header claims {expected} payload bytes, but only {actual} available")]
    FrameTruncated {
        /// Expected payload size from header
        expected: usize,
        /// Actual bytes available
        actual: usize,
    },

    // CBOR errors (wrapped for testability)
    /// Failed to encode data as CBOR
    #[error("failed to encode CBOR: {0}")]
    CborEncode(String),

    /// Failed to decode CBOR data
    #[error("failed to decode CBOR: {0}")]
    CborDecode(String),

    // Validation errors
    /// Invalid or unknown opcode
    #[error("invalid opcode: {0:#06x}")]
    InvalidOpcode(u16),

    /// Payload size in header doesn't match actual payload
    #[error("payload size mismatch: header says {header} bytes, actual {actual}")]
    PayloadSizeMismatch {
        /// Size claimed in header
        header: usize,
        /// Actual payload size
        actual: usize,
    },

    /// Invalid flag combination
    #[error("invalid flags: {0:#04x}")]
    InvalidFlags(u8),
}

/// Convenient Result type alias for protocol operations
pub type Result<T> = std::result::Result<T, ProtocolError>;

impl From<ProtocolError> for std::io::Error {
    fn from(err: ProtocolError) -> Self {
        Self::new(std::io::ErrorKind::InvalidData, err)
    }
}
