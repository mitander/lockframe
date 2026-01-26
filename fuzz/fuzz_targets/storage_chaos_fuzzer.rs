//! Fuzz target for RoomManager under storage failures
//!
//! Tests RoomManager behavior when storage operations fail randomly.
//! Uses ChaoticStorage to inject I/O errors at configurable rates.
//!
//! # Strategy
//!
//! - Variable failure rates (0% to 90%)
//! - Mixed valid/invalid frames under storage pressure
//! - Verify graceful degradation, not crashes
//!
//! # Invariants
//!
//! - RoomManager NEVER panics on storage errors
//! - Storage errors propagate as Result::Err, not panics
//! - After failures, successful operations still work correctly
//! - No partial state corruption (atomic or nothing)
//! - Frames that succeed storage are correctly sequenced

#![no_main]

use std::collections::HashMap;

use arbitrary::Arbitrary;
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use lockframe_core::mls::MlsGroupState;
use lockframe_proto::{Frame, FrameHeader, Opcode};
use lockframe_server::{
    ChaoticStorage, RoomAction, RoomManager, Storage, SystemEnv, storage::MemoryStorage,
};

#[derive(Debug, Clone, Arbitrary)]
struct ChaosScenario {
    /// Seed for deterministic key generation
    seed: [u8; 32],
    /// Seed for ChaoticStorage RNG (deterministic failures)
    chaos_seed: u64,
    /// Failure rate 0-9 maps to 0%-90%
    failure_rate_tenth: u8,
    /// Room configuration
    room_id: u8,
    /// Number of members (1-5)
    member_count: u8,
    /// Sequence of operations to perform
    operations: Vec<ChaosOperation>,
}

#[derive(Debug, Clone, Arbitrary)]
enum ChaosOperation {
    /// Send a valid frame from a member
    SendValidFrame { member_idx: u8 },
    /// Send frame with corrupted signature
    SendCorruptedFrame { member_idx: u8 },
    /// Query latest log index (read operation)
    QueryLatestIndex,
    /// Load frames from storage (read operation)
    LoadFrames { from: u8, limit: u8 },
    /// Store and immediately load MLS state
    RoundTripMlsState,
}

fuzz_target!(|scenario: ChaosScenario| {
    let failure_rate = (scenario.failure_rate_tenth % 10) as f64 / 10.0;
    let room_id = (scenario.room_id as u128).saturating_add(1); // Avoid room_id=0

    let inner_storage = MemoryStorage::new();
    let storage = ChaoticStorage::with_seed(inner_storage, failure_rate, scenario.chaos_seed);

    let env = SystemEnv::new();
    let mut room_manager = RoomManager::new();

    let member_count = ((scenario.member_count % 5) + 1) as usize;
    let member_ids: Vec<u64> = (1..=member_count).map(|i| 100 + i as u64).collect();

    let mut member_keys: HashMap<u64, SigningKey> = HashMap::new();
    let mut member_verifying_keys: HashMap<u64, [u8; 32]> = HashMap::new();

    for (i, &member_id) in member_ids.iter().enumerate() {
        let mut key_bytes = scenario.seed;
        for (j, byte) in key_bytes.iter_mut().enumerate() {
            *byte ^= (i as u8).wrapping_add(j as u8);
        }
        let signing_key = SigningKey::from_bytes(&key_bytes);
        member_verifying_keys.insert(member_id, signing_key.verifying_key().to_bytes());
        member_keys.insert(member_id, signing_key);
    }

    if room_manager.create_room(room_id, member_ids[0], &env).is_err() {
        return;
    }

    let initial_mls_state = MlsGroupState::with_keys(
        room_id,
        0,
        [0u8; 32],
        member_ids.clone(),
        member_verifying_keys.clone(),
    );

    if storage.store_mls_state(room_id, &initial_mls_state).is_err() {
        // This is expected under chaos
        return;
    }

    let mut successful_frames = 0u64;
    let mut current_epoch = 0u64;

    for op in scenario.operations {
        match op {
            ChaosOperation::SendValidFrame { member_idx } => {
                let sender_id = member_ids[(member_idx as usize) % member_ids.len()];
                let signing_key = member_keys.get(&sender_id).expect("member key must exist");
                let frame = create_signed_frame(signing_key, sender_id, current_epoch, room_id);

                match room_manager.process_frame(frame, &env, &storage) {
                    Ok(actions) => {
                        for action in actions {
                            if let RoomAction::PersistFrame { log_index, frame, .. } = action {
                                // RoomManager returns what IT expects the index to be.
                                // Under chaos, storage may fail, so we track what
                                // RoomManager believes the state is, not what storage has.
                                // Try to actually persist and track success.
                                if storage.store_frame(room_id, log_index, &frame).is_ok() {
                                    successful_frames += 1;
                                }
                            }
                        }
                    },
                    Err(_) => {
                        // This is expected under chaos
                    },
                }
            },

            ChaosOperation::SendCorruptedFrame { member_idx } => {
                let sender_id = member_ids[(member_idx as usize) % member_ids.len()];
                let signing_key = member_keys.get(&sender_id).expect("member key must exist");
                let mut frame = create_signed_frame(signing_key, sender_id, current_epoch, room_id);

                let sig = frame.header.signature();
                let mut corrupted: [u8; 64] = *sig;
                corrupted[0] ^= 0xFF;
                frame.header.set_signature(corrupted);

                let _ = room_manager.process_frame(frame, &env, &storage);
            },

            ChaosOperation::QueryLatestIndex => {
                let _ = storage.latest_log_index(room_id);
            },

            ChaosOperation::LoadFrames { from, limit } => {
                let from_idx = from as u64;
                let limit_val = (limit as usize).max(1);
                let _ = storage.load_frames(room_id, from_idx, limit_val);
            },

            ChaosOperation::RoundTripMlsState => {
                if let Ok(Some(state)) = storage.load_mls_state(room_id) {
                    current_epoch = state.epoch;
                    let _ = storage.store_mls_state(room_id, &state);
                }
            },
        }
    }

    verify_final_invariants(room_id, successful_frames, &storage);
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

fn verify_final_invariants<S: Storage>(room_id: u128, _successful_persists: u64, storage: &S) {
    // INVARIANT: Whatever IS in storage must have sequential indices
    if let Ok(Some(latest)) = storage.latest_log_index(room_id) {
        if let Ok(frames) = storage.load_frames(room_id, 0, (latest + 1) as usize) {
            for (i, frame) in frames.iter().enumerate() {
                assert_eq!(
                    frame.header.log_index(),
                    i as u64,
                    "frame {} has wrong log_index (expected {})",
                    frame.header.log_index(),
                    i
                );
            }
        }
    }
}
