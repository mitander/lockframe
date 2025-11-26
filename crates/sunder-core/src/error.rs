//! Error types for the Sunder protocol core.
//!
//! This module provides strongly-typed errors for different layers:
//! - Connection errors (handshake, timeout, state transitions)
//! - Transport errors (network failures)
//!
//! We avoid using `std::io::Error` for protocol logic to maintain type safety
//! and enable proper error handling and recovery.

use std::{fmt, io, time::Duration};

use crate::connection::ConnectionState;

/// Errors that can occur during connection state machine operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// Invalid state transition attempted
    InvalidState {
        /// Current state when error occurred
        state: ConnectionState,
        /// Operation that was attempted
        operation: String,
    },

    /// Received unexpected frame for current state
    UnexpectedFrame {
        /// Current state when frame was received
        state: ConnectionState,
        /// Opcode of the unexpected frame
        opcode: u16,
    },

    /// Handshake did not complete within timeout
    HandshakeTimeout {
        /// How long we waited
        elapsed: Duration,
    },

    /// Connection idle timeout exceeded
    IdleTimeout {
        /// How long connection was idle
        elapsed: Duration,
    },

    /// Unsupported protocol version
    UnsupportedVersion(u8),

    /// Invalid payload for opcode
    InvalidPayload {
        /// Expected payload type
        expected: &'static str,
        /// Opcode that was received
        opcode: u16,
    },

    /// Protocol error from frame parsing/validation
    Protocol(String),

    /// Underlying transport error
    Transport(String),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState { state, operation } => {
                write!(f, "invalid state transition: cannot {} from {:?}", operation, state)
            },
            Self::UnexpectedFrame { state, opcode } => {
                write!(f, "unexpected frame: received opcode {:#06x} in state {:?}", opcode, state)
            },
            Self::HandshakeTimeout { elapsed } => {
                write!(f, "handshake timeout after {:?}", elapsed)
            },
            Self::IdleTimeout { elapsed } => {
                write!(f, "idle timeout after {:?}", elapsed)
            },
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported protocol version: {}", version)
            },
            Self::InvalidPayload { expected, opcode } => {
                write!(f, "invalid payload: expected {} for opcode {:#06x}", expected, opcode)
            },
            Self::Protocol(msg) => write!(f, "protocol error: {}", msg),
            Self::Transport(msg) => write!(f, "transport error: {}", msg),
        }
    }
}

impl std::error::Error for ConnectionError {}

/// Convert ConnectionError to io::Error for compatibility with async I/O APIs.
///
/// This is only for boundary conversion - internally we use ConnectionError.
impl From<ConnectionError> for io::Error {
    fn from(err: ConnectionError) -> Self {
        let kind = match &err {
            ConnectionError::HandshakeTimeout { .. } | ConnectionError::IdleTimeout { .. } => {
                io::ErrorKind::TimedOut
            },
            ConnectionError::InvalidState { .. }
            | ConnectionError::UnexpectedFrame { .. }
            | ConnectionError::UnsupportedVersion(_)
            | ConnectionError::InvalidPayload { .. } => io::ErrorKind::InvalidData,
            ConnectionError::Protocol(_) => io::ErrorKind::InvalidData,
            ConnectionError::Transport(_) => io::ErrorKind::Other,
        };
        io::Error::new(kind, err.to_string())
    }
}

/// Convert sunder-proto errors to ConnectionError
impl From<sunder_proto::ProtocolError> for ConnectionError {
    fn from(err: sunder_proto::ProtocolError) -> Self {
        ConnectionError::Protocol(err.to_string())
    }
}

/// Convert io::Error to ConnectionError (for transport errors)
impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> Self {
        ConnectionError::Transport(err.to_string())
    }
}
