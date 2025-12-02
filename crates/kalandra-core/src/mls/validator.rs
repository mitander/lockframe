//! MLS frame validation for server sequencing
//!
//! This module provides minimal validation logic needed by the Sequencer.
//! It validates frames against current MLS state (epoch and membership)
//! without performing full MLS operations.

use kalandra_proto::Frame;

use super::{MlsError, MlsGroupState};

/// Result of validating a frame against MLS state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Frame is valid and should be sequenced
    Accept,

    /// Frame is invalid and should be rejected
    Reject {
        /// Human-readable reason for rejection
        reason: String,
    },
}

/// MLS frame validator
///
/// This validator performs lightweight checks needed by the sequencer:
/// - Epoch validation (frame matches current MLS epoch)
/// - Membership validation (sender is in the group)
///
/// It does NOT perform:
/// - Full MLS proposal/commit processing
/// - Signature verification (TODO: Phase 2 extension)
/// - Tree hash validation
pub struct MlsValidator;

impl MlsValidator {
    /// Validate a frame against current MLS group state
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if frame validation encounters an internal error.
    /// Note: Validation failures return `Ok(ValidationResult::Reject)`, not
    /// errors.
    pub fn validate_frame(
        frame: &Frame,
        current_epoch: u64,
        group_state: &MlsGroupState,
    ) -> Result<ValidationResult, MlsError> {
        // 1. Check epoch matches
        let frame_epoch = frame.header.epoch();
        if frame_epoch != current_epoch {
            return Ok(ValidationResult::Reject {
                reason: format!("epoch mismatch: expected {}, got {}", current_epoch, frame_epoch),
            });
        }

        // 2. Verify sender is member
        let sender_id = frame.header.sender_id();
        if !group_state.is_member(sender_id) {
            return Ok(ValidationResult::Reject {
                reason: format!("sender {} not in group", sender_id),
            });
        }

        // 3. TODO: Verify signature (Phase 2 extension)
        // Currently we trust the client signature. In production, we would:
        // - Extract sender's public key from group_state
        // - Verify Ed25519 signature over frame header
        // - Return Reject if signature invalid

        Ok(ValidationResult::Accept)
    }

    /// Validate a frame without MLS state (epoch 0, no membership check)
    ///
    /// This is used for the initial setup of a room before MLS is initialized.
    /// Only basic sanity checks are performed.
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if frame validation encounters an internal error.
    /// Note: Validation failures return `Ok(ValidationResult::Reject)`, not
    /// errors.
    pub fn validate_frame_no_state(frame: &Frame) -> Result<ValidationResult, MlsError> {
        // For now, accept all frames when no MLS state exists
        // In production, we might want to:
        // - Check that epoch is 0
        // - Validate frame is a Welcome or initial Commit
        // - Verify creator's credentials

        let frame_epoch = frame.header.epoch();
        if frame_epoch != 0 {
            return Ok(ValidationResult::Reject {
                reason: format!("no MLS state for room, expected epoch 0, got {}", frame_epoch),
            });
        }

        Ok(ValidationResult::Accept)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use kalandra_proto::{FrameHeader, Opcode};

    use super::*;

    fn create_test_frame(sender_id: u64, epoch: u64) -> Frame {
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_sender_id(sender_id);
        header.set_epoch(epoch);
        header.set_room_id(100);

        Frame::new(header, Bytes::new())
    }

    fn create_test_state(epoch: u64, members: Vec<u64>) -> MlsGroupState {
        MlsGroupState::new(100, epoch, [0u8; 32], members, vec![])
    }

    #[test]
    fn test_valid_frame_accepted() {
        let frame = create_test_frame(100, 5);
        let state = create_test_state(5, vec![100, 200, 300]);

        let result = MlsValidator::validate_frame(&frame, 5, &state).expect("validation failed");

        assert_eq!(result, ValidationResult::Accept);
    }

    #[test]
    fn test_old_epoch_rejected() {
        let frame = create_test_frame(100, 3);
        let state = create_test_state(5, vec![100, 200]);

        let result = MlsValidator::validate_frame(&frame, 5, &state).expect("validation failed");

        match result {
            ValidationResult::Reject { reason } => {
                assert!(reason.contains("epoch mismatch"));
                assert!(reason.contains("expected 5"));
                assert!(reason.contains("got 3"));
            },
            ValidationResult::Accept => panic!("Expected rejection for old epoch"),
        }
    }

    #[test]
    fn test_future_epoch_rejected() {
        let frame = create_test_frame(100, 7);
        let state = create_test_state(5, vec![100, 200]);

        let result = MlsValidator::validate_frame(&frame, 5, &state).expect("validation failed");

        match result {
            ValidationResult::Reject { reason } => {
                assert!(reason.contains("epoch mismatch"));
                assert!(reason.contains("expected 5"));
                assert!(reason.contains("got 7"));
            },
            ValidationResult::Accept => panic!("Expected rejection for future epoch"),
        }
    }

    #[test]
    fn test_non_member_rejected() {
        let frame = create_test_frame(999, 5); // sender 999 not in group
        let state = create_test_state(5, vec![100, 200, 300]);

        let result = MlsValidator::validate_frame(&frame, 5, &state).expect("validation failed");

        match result {
            ValidationResult::Reject { reason } => {
                assert!(reason.contains("sender 999"));
                assert!(reason.contains("not in group"));
            },
            ValidationResult::Accept => panic!("Expected rejection for non-member"),
        }
    }

    #[test]
    fn test_all_members_accepted() {
        let state = create_test_state(5, vec![100, 200, 300]);

        for sender in [100, 200, 300] {
            let frame = create_test_frame(sender, 5);
            let result =
                MlsValidator::validate_frame(&frame, 5, &state).expect("validation failed");
            assert_eq!(result, ValidationResult::Accept);
        }
    }

    #[test]
    fn test_validate_no_state_epoch_zero() {
        let frame = create_test_frame(100, 0);
        let result = MlsValidator::validate_frame_no_state(&frame).expect("validation failed");

        assert_eq!(result, ValidationResult::Accept);
    }

    #[test]
    fn test_validate_no_state_non_zero_epoch_rejected() {
        let frame = create_test_frame(100, 5);
        let result = MlsValidator::validate_frame_no_state(&frame).expect("validation failed");

        match result {
            ValidationResult::Reject { reason } => {
                assert!(reason.contains("no MLS state"));
                assert!(reason.contains("expected epoch 0"));
            },
            ValidationResult::Accept => panic!("Expected rejection for non-zero epoch"),
        }
    }
}
