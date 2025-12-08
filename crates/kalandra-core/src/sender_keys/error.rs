//! Error types for Sender Keys operations

use thiserror::Error;

/// Errors from sender key operations
#[derive(Debug, Error)]
pub enum SenderKeyError {
    /// Received message from unknown sender (not in our peer ratchets)
    #[error("unknown sender: {sender_index}")]
    UnknownSender {
        /// The sender index that was not found
        sender_index: u32,
    },

    /// Ratchet is too far behind the requested generation
    /// This can happen with severely out-of-order messages
    #[error("ratchet too far behind: at generation {current}, need {requested}")]
    RatchetTooFarBehind {
        /// Current ratchet generation
        current: u32,
        /// Requested generation
        requested: u32,
    },

    /// Decryption failed (authentication tag mismatch)
    #[error("decryption failed: {reason}")]
    DecryptionFailed {
        /// Reason for decryption failure
        reason: String,
    },

    /// Message epoch doesn't match our current epoch
    #[error("epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch {
        /// Expected epoch
        expected: u64,
        /// Actual epoch in message
        actual: u64,
    },

    /// Invalid key material length
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length
        expected: usize,
        /// Actual key length
        actual: usize,
    },

    /// Ratchet generation would overflow
    #[error("ratchet generation overflow at {current}")]
    GenerationOverflow {
        /// Current generation when overflow was detected
        current: u32,
    },
}

impl SenderKeyError {
    /// Returns true if this error is fatal (unrecoverable)
    ///
    /// Fatal errors indicate a protocol violation or bug.
    /// Transient errors may be recoverable with retry or state sync.
    pub fn is_fatal(&self) -> bool {
        match self {
            // Protocol violations - fatal
            Self::DecryptionFailed { .. } => true,
            Self::InvalidKeyLength { .. } => true,
            Self::GenerationOverflow { .. } => true,

            // Potentially recoverable - need state sync
            Self::UnknownSender { .. } => false,
            Self::RatchetTooFarBehind { .. } => false,
            Self::EpochMismatch { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decryption_failed_is_fatal() {
        let err = SenderKeyError::DecryptionFailed { reason: "tag mismatch".to_string() };
        assert!(err.is_fatal());
    }

    #[test]
    fn unknown_sender_is_not_fatal() {
        let err = SenderKeyError::UnknownSender { sender_index: 42 };
        assert!(!err.is_fatal());
    }

    #[test]
    fn epoch_mismatch_is_not_fatal() {
        let err = SenderKeyError::EpochMismatch { expected: 5, actual: 3 };
        assert!(!err.is_fatal());
    }

    #[test]
    fn error_display() {
        let err = SenderKeyError::RatchetTooFarBehind { current: 10, requested: 100 };
        assert_eq!(err.to_string(), "ratchet too far behind: at generation 10, need 100");
    }
}
