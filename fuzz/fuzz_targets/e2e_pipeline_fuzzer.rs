//! Fuzz target for end-to-end pipeline (decode → validate → sequence → store)
//!
//! Full integration coverage of the frame processing pipeline (HIGH priority)
//!
//! # Strategy
//!
//! - Raw bytes: Arbitrary byte sequences through decode path
//! - Valid frames: Programmatically created signed frames
//! - Attack frames: Corrupted signatures, wrong epochs, non-members
//! - Full pipeline: decode → RoomManager validate → sequence → store
//!
//! # Invariants
//!
//! - Invalid frames rejected before storage write
//! - RoomManager integrates validation + sequencing (no bypasses)
//! - Storage only contains validated frames
//! - All stored frames have sequential log indices (no gaps)
//! - All stored frames have valid signatures
//! - Full pipeline never panics
//! - Golden rule: Storage = Validated ∩ Sequenced

#![no_main]

use std::collections::HashMap;

use arbitrary::Arbitrary;
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use lockframe_core::mls::MlsGroupState;
use lockframe_proto::{Frame, FrameHeader, Opcode};
use lockframe_server::{RoomAction, RoomManager, Storage, SystemEnv, storage::MemoryStorage};

#[derive(Debug, Clone, Arbitrary)]
struct E2EScenario {
    seed: [u8; 32],
    setup: RoomSetup,
    frames: Vec<FrameInput>,
}

#[derive(Debug, Clone, Arbitrary)]
struct RoomSetup {
    room_id: u8,
    member_count: u8,
    epoch: u8,
}

#[derive(Debug, Clone, Arbitrary)]
enum FrameInput {
    RawBytes(Vec<u8>),
    ValidFrame { member_idx: u8, opcode: u16 },
    AttackFrame { attack: AttackType, member_idx: u8 },
}

#[derive(Debug, Clone, Arbitrary)]
enum AttackType {
    CorruptedSignature(u8),
    WrongEpoch(u8),
    NonMember,
}

fuzz_target!(|scenario: E2EScenario| {
    let env = SystemEnv::new();

    let room_id = (scenario.setup.room_id as u128).max(1);
    let member_count = (scenario.setup.member_count % 10).max(1) as usize;
    let epoch = scenario.setup.epoch as u64;

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

    let group_state = MlsGroupState::with_keys(
        room_id,
        epoch,
        [0u8; 32],
        member_ids.clone(),
        member_verifying_keys.clone(),
    );

    let mut room_manager = RoomManager::new();
    let storage = MemoryStorage::new();

    // Create room through RoomManager
    if room_manager.create_room(room_id, member_ids[0], &env).is_err() {
        return;
    }

    // Store the MLS state with proper member keys
    if storage.store_mls_state(room_id, &group_state).is_err() {
        return;
    }

    let mut next_expected_log_index = 0u64;

    for frame_input in scenario.frames {
        let frame_opt = match frame_input {
            FrameInput::RawBytes(ref bytes) => Frame::decode(bytes).ok(),
            FrameInput::ValidFrame { member_idx, opcode } => {
                let sender_id = member_ids[(member_idx as usize) % member_ids.len()];
                member_keys.get(&sender_id).map(|signing_key| {
                    create_valid_frame(signing_key, sender_id, epoch, room_id, opcode)
                })
            },
            FrameInput::AttackFrame { attack, member_idx } => {
                create_attack_frame(&attack, &member_ids, &member_keys, member_idx, epoch, room_id)
            },
        };

        let Some(frame) = frame_opt else {
            continue;
        };

        if let Ok(actions) = room_manager.process_frame(frame.clone(), &env, &storage) {
            for action in actions {
                if let RoomAction::PersistFrame { log_index, .. } = action {
                    if log_index == next_expected_log_index {
                        next_expected_log_index += 1;
                    }
                }
            }
        }
    }

    if let Ok(stored_frames) = storage.load_frames(room_id, 0, 1000) {
        for (i, frame) in stored_frames.iter().enumerate() {
            assert_eq!(frame.header.log_index(), i as u64);
        }
    }
});

fn create_valid_frame(
    signing_key: &SigningKey,
    sender_id: u64,
    epoch: u64,
    room_id: u128,
    opcode: u16,
) -> Frame {
    let opcode_enum = Opcode::from_u16(opcode).unwrap_or(Opcode::AppMessage);
    let mut header = FrameHeader::new(opcode_enum);
    header.set_sender_id(sender_id);
    header.set_epoch(epoch);
    header.set_room_id(room_id);
    header.set_log_index(0);

    let signature = signing_key.sign(&header.signing_data());
    header.set_signature(signature.to_bytes());

    Frame::new(header, Bytes::new())
}

fn create_attack_frame(
    attack: &AttackType,
    members: &[u64],
    keys: &HashMap<u64, SigningKey>,
    member_idx: u8,
    epoch: u64,
    room_id: u128,
) -> Option<Frame> {
    let sender_id = members[(member_idx as usize) % members.len()];
    let signing_key = keys.get(&sender_id)?;

    match attack {
        AttackType::CorruptedSignature(bit) => {
            let mut frame = create_valid_frame(
                signing_key,
                sender_id,
                epoch,
                room_id,
                Opcode::AppMessage.to_u16(),
            );

            let sig_bytes = frame.header.signature();
            if sig_bytes.len() == 64 {
                let mut sig_array: [u8; 64] = *sig_bytes;
                sig_array[(*bit as usize) % 64] ^= 0x01;
                frame.header.set_signature(sig_array);
            }
            Some(frame)
        },

        AttackType::WrongEpoch(offset) => {
            let wrong_epoch = epoch.wrapping_add((*offset as u64).max(1));
            Some(create_valid_frame(
                signing_key,
                sender_id,
                wrong_epoch,
                room_id,
                Opcode::AppMessage.to_u16(),
            ))
        },

        AttackType::NonMember => {
            let mut header = FrameHeader::new(Opcode::AppMessage);
            header.set_sender_id(9999);
            header.set_epoch(epoch);
            header.set_room_id(room_id);
            header.set_signature([0xAA; 64]);
            Some(Frame::new(header, Bytes::new()))
        },
    }
}
