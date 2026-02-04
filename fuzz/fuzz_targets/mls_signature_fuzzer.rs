//! Fuzz target for MLS signature verification
//!
//! Prevent signature forgery and verification bypass (CRITICAL security
//! boundary)
//!
//! # Strategy
//!
//! - Corrupted signatures: Flip bits in valid signature bytes
//! - Wrong keys: Sign with one key, verify with another
//! - Tampered data: Modify signed frame fields after signing
//!
//! # Invariants
//!
//! - Valid signature MUST return `ValidationResult::Accept`
//! - Corrupted signature (any bit flip) MUST return `ValidationResult::Reject`
//! - Signature from wrong key MUST reject
//! - Tampered frame data MUST reject (signature doesn't match)
//! - Malformed signature bytes (wrong length, all-zeros) MUST reject
//! - NEVER panic on invalid signature input

#![no_main]

use std::collections::HashMap;

use arbitrary::Arbitrary;
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use lockframe_core::mls::{MlsGroupState, MlsValidator, ValidationResult};
use lockframe_proto::{Frame, FrameHeader, Opcode};

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    seed: [u8; 32],
    attack: SignatureAttack,
}

#[derive(Debug, Clone, Arbitrary)]
enum SignatureAttack {
    CorruptedSignature { byte_offset: u8, bit_offset: u8 },
    WrongKey { signing_key: SigningKeyChoice },
    TamperedData { field: TamperedField },
    MalformedSignature { malformed: MalformedType },
}

#[derive(Debug, Clone, Arbitrary)]
enum TamperedField {
    RoomId(u128),
    SenderId(u64),
    Epoch(u64),
}

#[derive(Debug, Clone, Arbitrary)]
enum MalformedType {
    AllZeros,
    PatternFill(u8),
    HighEntropyGarbage,
}

#[derive(Debug, Clone, Arbitrary)]
enum SigningKeyChoice {
    First,
    Second,
}

fn derive_key_bytes(seed: &[u8; 32], index: u8) -> [u8; 32] {
    let mut key_bytes = *seed;
    for (i, byte) in key_bytes.iter_mut().enumerate() {
        *byte ^= index.wrapping_add(i as u8);
    }
    key_bytes
}

fuzz_target!(|input: FuzzInput| {
    let key1 = SigningKey::from_bytes(&derive_key_bytes(&input.seed, 0));
    let key2 = SigningKey::from_bytes(&derive_key_bytes(&input.seed, 1));
    let verifying_key1 = key1.verifying_key();
    let verifying_key2 = key2.verifying_key();

    let room_id = 100u128;
    let sender_id = 1u64;
    let epoch = 5u64;

    match input.attack {
        SignatureAttack::CorruptedSignature { byte_offset, bit_offset } => {
            let frame = create_signed_frame(&key1, sender_id, epoch, room_id);
            let state = create_group_state(room_id, epoch, vec![sender_id], &verifying_key1);

            let original_result = MlsValidator::validate_signature(&frame, &state);
            assert_eq!(original_result, ValidationResult::Accept);
            assert_eq!(original_result, ValidationResult::Accept);

            let mut corrupted_frame = frame.clone();
            let sig_bytes = corrupted_frame.header.signature();

            if sig_bytes.len() == 64 {
                let byte_idx = (byte_offset as usize) % 64;
                let bit_idx = bit_offset % 8;

                let mut sig_array: [u8; 64] = *sig_bytes;
                sig_array[byte_idx] ^= 1 << bit_idx;
                corrupted_frame.header.set_signature(sig_array);

                let result = MlsValidator::validate_signature(&corrupted_frame, &state);
                assert!(matches!(result, ValidationResult::Reject { .. }));

                if let ValidationResult::Accept = result {
                    panic!(
                        "SECURITY VIOLATION: Corrupted signature accepted! \
                         Flipped byte {} bit {}",
                        byte_idx, bit_idx
                    );
                }
            }
        },

        SignatureAttack::WrongKey { signing_key } => {
            let (signing_key, verifying_key) = match signing_key {
                SigningKeyChoice::First => (&key1, &verifying_key2),
                SigningKeyChoice::Second => (&key2, &verifying_key1),
            };

            let frame = create_signed_frame(signing_key, sender_id, epoch, room_id);
            let state = create_group_state(room_id, epoch, vec![sender_id], verifying_key);

            let result = MlsValidator::validate_signature(&frame, &state);
            assert!(matches!(result, ValidationResult::Reject { .. }));

            if let ValidationResult::Accept = result {
                panic!("SECURITY VIOLATION: Signature from wrong key accepted!");
            }
        },

        SignatureAttack::TamperedData { field } => {
            let original_frame = create_signed_frame(&key1, sender_id, epoch, room_id);
            let state = create_group_state(room_id, epoch, vec![sender_id], &verifying_key1);

            let original_result = MlsValidator::validate_signature(&original_frame, &state);
            assert_eq!(original_result, ValidationResult::Accept);
            assert_eq!(original_result, ValidationResult::Accept);

            let mut tampered = original_frame.clone();

            let actually_tampered = match field {
                TamperedField::RoomId(v) if v != tampered.header.room_id() => {
                    tampered.header.set_room_id(v);
                    true
                },
                TamperedField::SenderId(v) if v != tampered.header.sender_id() => {
                    tampered.header.set_sender_id(v);
                    true
                },
                TamperedField::Epoch(v) if v != tampered.header.epoch() => {
                    tampered.header.set_epoch(v);
                    true
                },
                _ => false,
            };

            if !actually_tampered {
                return;
            }

            let result = MlsValidator::validate_signature(&tampered, &state);
            assert!(matches!(result, ValidationResult::Reject { .. }));

            if let ValidationResult::Accept = result {
                panic!("SECURITY VIOLATION: Tampered frame accepted! Modified {:?}", field);
            }
        },

        SignatureAttack::MalformedSignature { malformed } => {
            let mut header = FrameHeader::new(Opcode::AppMessage);
            header.set_sender_id(sender_id);
            header.set_epoch(epoch);
            header.set_room_id(room_id);

            let malformed_sig: [u8; 64] = match malformed {
                MalformedType::AllZeros => [0u8; 64],
                MalformedType::PatternFill(seed) => {
                    let mut sig = [0u8; 64];
                    for (i, byte) in sig.iter_mut().enumerate() {
                        *byte = seed.wrapping_mul(7).wrapping_add(i as u8);
                    }
                    sig
                },
                MalformedType::HighEntropyGarbage => {
                    let mut sig = [0u8; 64];
                    for (i, byte) in sig.iter_mut().enumerate() {
                        *byte = (i as u8).wrapping_mul(7).wrapping_add(13);
                    }
                    sig
                },
            };

            header.set_signature(malformed_sig);
            let frame = Frame::new(header, Bytes::new());
            let state = create_group_state(room_id, epoch, vec![sender_id], &verifying_key1);

            let result = MlsValidator::validate_signature(&frame, &state);
            assert!(matches!(result, ValidationResult::Reject { .. }));

            if let ValidationResult::Accept = result {
                panic!("SECURITY VIOLATION: Malformed signature accepted!");
            }
        },
    }
});

fn create_signed_frame(
    signing_key: &SigningKey,
    sender_id: u64,
    epoch: u64,
    room_id: u128,
) -> Frame {
    let mut header = FrameHeader::new(Opcode::AppMessage);
    header.set_sender_id(sender_id);
    header.set_epoch(epoch);
    header.set_room_id(room_id);
    header.set_log_index(0);

    let signature = signing_key.sign(&header.signing_data());
    header.set_signature(signature.to_bytes());

    Frame::new(header, Bytes::new())
}

fn create_group_state(
    room_id: u128,
    epoch: u64,
    members: Vec<u64>,
    verifying_key: &VerifyingKey,
) -> MlsGroupState {
    let mut member_keys = HashMap::new();
    for &member_id in &members {
        member_keys.insert(member_id, verifying_key.to_bytes());
    }

    MlsGroupState::with_keys(room_id, epoch, [0u8; 32], members, member_keys)
}
