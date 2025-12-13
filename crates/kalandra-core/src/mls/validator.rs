//! MLS frame validation for server sequencing
//!
//! This module provides minimal validation logic needed by the Sequencer.
//! It validates frames against current MLS state (epoch, membership, and
//! signature) without performing full MLS operations.

use ed25519_dalek::{Signature, Verifier};
use kalandra_proto::Frame;

use super::{MlsError, MlsGroupState, constants::MAX_EPOCH};

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
/// - Signature verification (Ed25519 over frame header)
///
/// It does NOT perform:
/// - Full MLS proposal/commit processing
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
        debug_assert!(current_epoch < MAX_EPOCH);

        let frame_epoch = frame.header.epoch();
        if frame_epoch != current_epoch {
            return Ok(ValidationResult::Reject {
                reason: format!("epoch mismatch: expected {}, got {}", current_epoch, frame_epoch),
            });
        }

        debug_assert_eq!(frame_epoch, current_epoch);

        let sender_id = frame.header.sender_id();
        if !group_state.is_member(sender_id) {
            return Ok(ValidationResult::Reject {
                reason: format!("sender {} not in group", sender_id),
            });
        }

        debug_assert!(group_state.is_member(sender_id));

        if let Some(verifying_key) = group_state.member_key(sender_id) {
            let signature_bytes = frame.header.signature();

            let signature: Signature = match signature_bytes.as_slice().try_into() {
                Ok(sig) => sig,
                Err(_) => {
                    return Ok(ValidationResult::Reject {
                        reason: "invalid signature format".to_string(),
                    });
                },
            };

            let header_bytes = frame.header.to_bytes();
            let signed_data = &header_bytes[..64];

            if verifying_key.verify(signed_data, &signature).is_err() {
                return Ok(ValidationResult::Reject {
                    reason: format!("signature verification failed for sender {}", sender_id),
                });
            }
        }

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
        // TODO: Right now we accept all frames here, we might want to:
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

    #[test]
    fn test_valid_signature_accepted() {
        use std::collections::HashMap;

        use ed25519_dalek::{Signer, SigningKey};

        // Generate a signing key pair
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        // Create a frame and sign it
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_sender_id(100);
        header.set_epoch(5);
        header.set_room_id(100);

        // Get header bytes and sign the first 64 bytes
        let header_bytes = header.to_bytes();
        let signed_data = &header_bytes[..64];
        let signature = signing_key.sign(signed_data);

        // Set the signature in the header
        let mut signed_header = header;
        signed_header.set_signature(signature.to_bytes());

        let frame = Frame::new(signed_header, Bytes::new());

        // Create state with the public key
        let mut member_keys = HashMap::new();
        member_keys.insert(100, verifying_key.to_bytes());
        let state = MlsGroupState::with_keys(100, 5, [0u8; 32], vec![100], member_keys, vec![]);

        let result = MlsValidator::validate_frame(&frame, 5, &state).expect("validation failed");
        assert_eq!(result, ValidationResult::Accept);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        use std::collections::HashMap;

        use ed25519_dalek::{Signer, SigningKey};

        // Generate two different key pairs
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let wrong_verifying_key = SigningKey::generate(&mut rand::thread_rng()).verifying_key();

        // Create a frame and sign it with one key
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_sender_id(100);
        header.set_epoch(5);
        header.set_room_id(100);

        let header_bytes = header.to_bytes();
        let signed_data = &header_bytes[..64];
        let signature = signing_key.sign(signed_data);

        let mut signed_header = header;
        signed_header.set_signature(signature.to_bytes());

        let frame = Frame::new(signed_header, Bytes::new());

        // Create state with the WRONG public key
        let mut member_keys = HashMap::new();
        member_keys.insert(100, wrong_verifying_key.to_bytes());
        let state = MlsGroupState::with_keys(100, 5, [0u8; 32], vec![100], member_keys, vec![]);

        let result = MlsValidator::validate_frame(&frame, 5, &state).expect("validation failed");

        match result {
            ValidationResult::Reject { reason } => {
                assert!(reason.contains("signature verification failed"));
            },
            ValidationResult::Accept => panic!("Expected rejection for invalid signature"),
        }
    }

    #[test]
    fn test_no_key_skips_signature_check() {
        // Frame without signature verification (no public key stored)
        let frame = create_test_frame(100, 5);
        let state = create_test_state(5, vec![100, 200, 300]);

        // Should still accept (backwards compatibility)
        let result = MlsValidator::validate_frame(&frame, 5, &state).expect("validation failed");
        assert_eq!(result, ValidationResult::Accept);
    }
}
