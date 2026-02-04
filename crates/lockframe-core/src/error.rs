//! Error types for the Lockframe protocol core.
//!
//! Strongly-typed errors for different layers: connection errors (handshake,
//! timeout, state transitions) and transport errors (network failures).
//!
//! We avoid using `std::io::Error` for protocol logic to maintain type safety
//! and enable proper error handling and recovery.

use std::{io, time::Duration};

use thiserror::Error;

use crate::connection::ConnectionState;

/// Errors that can occur during connection state machine operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// Invalid state transition attempted
    #[error("invalid state transition: cannot {operation} from {state:?}")]
    InvalidState {
        /// Current state when error occurred
        state: ConnectionState,
        /// Operation that was attempted
        operation: String,
    },

    /// Received unexpected frame for current state
    #[error("unexpected frame: received opcode {opcode:#06x} in state {state:?}")]
    UnexpectedFrame {
        /// Current state when frame was received
        state: ConnectionState,
        /// Opcode of the unexpected frame
        opcode: u16,
    },

    /// Handshake did not complete within timeout
    #[error("handshake timeout after {elapsed:?}")]
    HandshakeTimeout {
        /// How long we waited
        elapsed: Duration,
    },

    /// Connection idle timeout exceeded
    #[error("idle timeout after {elapsed:?}")]
    IdleTimeout {
        /// How long connection was idle
        elapsed: Duration,
    },

    /// Unsupported protocol version
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Invalid payload for opcode
    #[error("invalid payload: expected {expected} for opcode {opcode:#06x}")]
    InvalidPayload {
        /// Expected payload type
        expected: &'static str,
        /// Opcode that was received
        opcode: u16,
    },

    /// Protocol error from frame parsing/validation
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Underlying transport error
    #[error("transport error: {0}")]
    Transport(String),
}

impl ConnectionError {
    /// Returns true if this error is transient and may succeed on retry.
    ///
    /// Transient errors are typically timeouts or temporary network issues.
    /// Protocol violations (invalid frames, unsupported versions) are never
    /// transient - they indicate a broken or malicious peer.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::HandshakeTimeout { .. } | Self::IdleTimeout { .. })
    }
}

/// Convert `ConnectionError` to `io::Error` for compatibility with async I/O
/// APIs.
///
/// This is only for boundary conversion - internally we use `ConnectionError`.
impl From<ConnectionError> for io::Error {
    fn from(err: ConnectionError) -> Self {
        let kind = match &err {
            ConnectionError::HandshakeTimeout { .. } | ConnectionError::IdleTimeout { .. } => {
                io::ErrorKind::TimedOut
            },
            ConnectionError::InvalidState { .. }
            | ConnectionError::UnexpectedFrame { .. }
            | ConnectionError::UnsupportedVersion(_)
            | ConnectionError::Protocol(_)
            | ConnectionError::InvalidPayload { .. } => io::ErrorKind::InvalidData,
            ConnectionError::Transport(_) => io::ErrorKind::Other,
        };
        Self::new(kind, err.to_string())
    }
}

/// Convert lockframe-proto errors to `ConnectionError`
impl From<lockframe_proto::ProtocolError> for ConnectionError {
    fn from(err: lockframe_proto::ProtocolError) -> Self {
        Self::Protocol(err.to_string())
    }
}

/// Convert `io::Error` to `ConnectionError` (for transport errors)
impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> Self {
        Self::Transport(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_errors_are_transient() {
        assert!(
            ConnectionError::HandshakeTimeout { elapsed: Duration::from_secs(31) }.is_transient()
        );

        assert!(ConnectionError::IdleTimeout { elapsed: Duration::from_secs(61) }.is_transient());
    }

    #[test]
    fn protocol_violations_are_fatal() {
        assert!(
            !ConnectionError::InvalidState {
                state: ConnectionState::Init,
                operation: "send_ping".to_string(),
            }
            .is_transient()
        );

        assert!(
            !ConnectionError::UnexpectedFrame { state: ConnectionState::Init, opcode: 0x03 }
                .is_transient()
        );

        assert!(!ConnectionError::UnsupportedVersion(99).is_transient());

        assert!(
            !ConnectionError::InvalidPayload { expected: "Hello", opcode: 0x01 }.is_transient()
        );

        assert!(!ConnectionError::Protocol("test error".to_string()).is_transient());

        assert!(!ConnectionError::Transport("network error".to_string()).is_transient());
    }
}
