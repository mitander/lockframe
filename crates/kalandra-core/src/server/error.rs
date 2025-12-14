//! Server error types.
//!
//! Provides strongly-typed errors for server operations:
//! - Session management (registration, lookup)
//! - Room subscription (subscribe, unsubscribe)
//! - Action execution (send, broadcast, persist)

use std::fmt;

use crate::{room_manager::RoomError, storage::StorageError};

/// Errors that can occur during server operations.
#[derive(Debug)]
pub enum ServerError {
    /// Session not found in registry
    SessionNotFound(u64),

    /// Session already registered
    SessionAlreadyExists(u64),

    /// Room operation failed
    Room(RoomError),

    /// Storage operation failed
    Storage(StorageError),

    /// Connection error during send
    ConnectionFailed {
        /// Session that failed
        session_id: u64,
        /// Error message
        reason: String,
    },

    /// Frame encoding/decoding error
    Protocol(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionNotFound(id) => write!(f, "session not found: {}", id),
            Self::SessionAlreadyExists(id) => write!(f, "session already exists: {}", id),
            Self::Room(err) => write!(f, "room error: {}", err),
            Self::Storage(err) => write!(f, "storage error: {}", err),
            Self::ConnectionFailed { session_id, reason } => {
                write!(f, "connection failed for session {}: {}", session_id, reason)
            },
            Self::Protocol(msg) => write!(f, "protocol error: {}", msg),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Room(err) => Some(err),
            Self::Storage(err) => Some(err),
            _ => None,
        }
    }
}

impl From<RoomError> for ServerError {
    fn from(err: RoomError) -> Self {
        Self::Room(err)
    }
}

impl From<StorageError> for ServerError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<kalandra_proto::ProtocolError> for ServerError {
    fn from(err: kalandra_proto::ProtocolError) -> Self {
        Self::Protocol(err.to_string())
    }
}

/// Errors from action execution.
#[derive(Debug)]
pub enum ExecutorError {
    /// Send to session failed
    SendFailed {
        /// Session that failed
        session_id: u64,
        /// Error message
        reason: String,
    },

    /// Storage write failed
    StorageFailed(String),

    /// Transport error
    Transport(String),
}

impl fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendFailed { session_id, reason } => {
                write!(f, "send failed for session {}: {}", session_id, reason)
            },
            Self::StorageFailed(msg) => write!(f, "storage failed: {}", msg),
            Self::Transport(msg) => write!(f, "transport error: {}", msg),
        }
    }
}

impl std::error::Error for ExecutorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_error_display() {
        let err = ServerError::SessionNotFound(42);
        assert_eq!(err.to_string(), "session not found: 42");

        let err = ServerError::SessionAlreadyExists(123);
        assert_eq!(err.to_string(), "session already exists: 123");

        let err = ServerError::ConnectionFailed { session_id: 1, reason: "timeout".to_string() };
        assert_eq!(err.to_string(), "connection failed for session 1: timeout");
    }

    #[test]
    fn executor_error_display() {
        let err = ExecutorError::SendFailed { session_id: 42, reason: "closed".to_string() };
        assert_eq!(err.to_string(), "send failed for session 42: closed");

        let err = ExecutorError::StorageFailed("disk full".to_string());
        assert_eq!(err.to_string(), "storage failed: disk full");
    }
}
