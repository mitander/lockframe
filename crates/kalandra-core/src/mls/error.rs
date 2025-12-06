//! MLS error types.

use std::time::Duration;

use thiserror::Error;

/// Errors that can occur during MLS operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum MlsError {
    /// Serialization/deserialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Unexpected message type
    #[error("unexpected message type: {0}")]
    UnexpectedMessage(String),

    /// Invalid state transition
    #[error("invalid state: cannot {operation} in epoch {epoch}")]
    InvalidState {
        /// Current epoch
        epoch: u64,
        /// Operation that was attempted
        operation: String,
    },

    /// Epoch mismatch (received message for wrong epoch)
    #[error("epoch mismatch: expected {expected}, received {received}")]
    EpochMismatch {
        /// Expected epoch number
        expected: u64,
        /// Received epoch number
        received: u64,
    },

    /// Member not found in group
    #[error("member not found: {member_id}")]
    MemberNotFound {
        /// Member ID that was not found
        member_id: u64,
    },

    /// Member already exists in group
    #[error("member already exists: {member_id}")]
    MemberAlreadyExists {
        /// Member ID that already exists
        member_id: u64,
    },

    /// Invalid proposal
    #[error("invalid proposal: {reason}")]
    InvalidProposal {
        /// Reason the proposal is invalid
        reason: String,
    },

    /// Invalid commit
    #[error("invalid commit: {reason}")]
    InvalidCommit {
        /// Reason the commit is invalid
        reason: String,
    },

    /// Cryptographic operation failed
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Encoding/decoding error
    #[error("codec error: {0}")]
    Codec(String),

    /// Protocol violation
    #[error("protocol violation: {0}")]
    Protocol(String),

    /// Not a member of the group
    #[error("not a member of group")]
    NotMember,

    /// Timeout waiting for operation
    #[error("timeout after {elapsed:?}")]
    Timeout {
        /// Time elapsed before timeout
        elapsed: Duration,
    },

    /// MLS group not found in storage
    #[error("group not found")]
    GroupNotFound,

    /// Frame validation failed
    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

impl MlsError {
    /// Returns true if this error is transient (can be retried).
    ///
    /// Transient errors:
    /// - Epoch mismatch (another commit was accepted first)
    /// - Timeout
    ///
    /// Non-transient errors:
    /// - Invalid state
    /// - Crypto errors
    /// - Protocol violations
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::EpochMismatch { .. } | Self::Timeout { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transient_errors() {
        let epoch_err = MlsError::EpochMismatch { expected: 5, received: 4 };
        assert!(epoch_err.is_transient());

        let timeout_err = MlsError::Timeout { elapsed: Duration::from_secs(30) };
        assert!(timeout_err.is_transient());
    }

    #[test]
    fn test_fatal_errors() {
        let state_err = MlsError::InvalidState { epoch: 5, operation: "commit".to_string() };
        assert!(!state_err.is_transient());

        let crypto_err = MlsError::Crypto("signature verification failed".to_string());
        assert!(!crypto_err.is_transient());

        let protocol_err = MlsError::Protocol("invalid tree hash".to_string());
        assert!(!protocol_err.is_transient());
    }
}
