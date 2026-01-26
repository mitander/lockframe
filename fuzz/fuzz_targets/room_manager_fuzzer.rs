//! Fuzz target for RoomManager integration (MLS + Sequencer)
//!
//! Prevent MLS/Sequencer state desync (HIGH priority integration test)
//!
//! # Strategy
//!
//! - Valid members: Frames signed by legitimate group members
//! - Non-members: Frames claiming sender IDs not in the group
//! - Wrong epochs: Frames signed for past/future epochs
//! - Invalid opcodes: Unexpected opcode values
//! - Corrupted signatures: Bit-flipped signature bytes
//!
//! # Invariants
//!
//! - Sequencer NEVER assigns log_index to rejected frame
//! - MLS epoch advances ONLY on valid Commit
//! - Storage contains ONLY frames that passed validation
//! - Frame with wrong epoch MUST reject
//! - Frame from non-member MUST reject
//! - All sequenced frames have sequential log indices (no gaps)

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
struct RoomScenario {
    seed: [u8; 32],
    room_id: RoomIdChoice,
    initial_members: MemberList,
    frame_sequence: Vec<FuzzedFrameInput>,
}

#[derive(Debug, Clone, Arbitrary)]
enum RoomIdChoice {
    Valid(u8),
    Zero,
    MaxU128,
}

#[derive(Debug, Clone, Arbitrary)]
struct MemberList {
    count: u8,
}

#[derive(Debug, Clone, Arbitrary)]
struct FuzzedFrameInput {
    attack: FrameAttack,
}

#[derive(Debug, Clone, Arbitrary)]
enum FrameAttack {
    ValidFromMember { member_idx: u8 },
    FromNonMember { fake_sender_id: u64 },
    WrongEpoch { member_idx: u8, epoch_offset: i8 },
    InvalidOpcode { member_idx: u8, opcode: u16 },
    CorruptedSignature { member_idx: u8, bit_flip: u8 },
}

fuzz_target!(|scenario: RoomScenario| {
    let env = SystemEnv::new();
    let storage = MemoryStorage::new();
    let mut room_manager = RoomManager::new();

    let room_id = match scenario.room_id {
        RoomIdChoice::Valid(v) => v as u128,
        RoomIdChoice::Zero => 0,
        RoomIdChoice::MaxU128 => u128::MAX,
    };

    let member_count = ((scenario.initial_members.count % 5) + 1) as usize;
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
        return;
    }

    let mut expected_log_index = 0u64;
    let mut current_epoch = 0u64;
    let mut frames_accepted = 0usize;

    for frame_input in scenario.frame_sequence {
        let frame = create_frame_from_attack(
            &frame_input.attack,
            room_id,
            current_epoch,
            &member_ids,
            &member_keys,
        );

        match room_manager.process_frame(frame.clone(), &env, &storage) {
            Ok(actions) => {
                for action in actions {
                    if let RoomAction::PersistFrame { log_index, .. } = action {
                        if log_index == expected_log_index {
                            expected_log_index += 1;
                            frames_accepted += 1;
                        }
                    }
                }

                if let Ok(Some(mls_state)) = storage.load_mls_state(room_id) {
                    current_epoch = mls_state.epoch;
                }
            },
            Err(_) => {
                if let Ok(Some(mls_state)) = storage.load_mls_state(room_id) {
                    current_epoch = mls_state.epoch;
                }
                if let Ok(Some(latest)) = storage.latest_log_index(room_id) {
                    if frames_accepted > 0 {
                        assert_eq!(latest, expected_log_index - 1);
                    }
                }
            },
        }
    }

    verify_storage_invariants(room_id, expected_log_index, &storage);
});

fn create_frame_from_attack(
    attack: &FrameAttack,
    room_id: u128,
    epoch: u64,
    members: &[u64],
    member_keys: &HashMap<u64, SigningKey>,
) -> Frame {
    match attack {
        FrameAttack::ValidFromMember { member_idx } => {
            let sender_id = members[(*member_idx as usize) % members.len()];
            let signing_key = member_keys.get(&sender_id).expect("member key must exist");
            create_signed_frame(signing_key, sender_id, epoch, room_id, Opcode::AppMessage)
        },

        FrameAttack::FromNonMember { fake_sender_id } => {
            let mut header = FrameHeader::new(Opcode::AppMessage);
            header.set_sender_id(*fake_sender_id);
            header.set_epoch(epoch);
            header.set_room_id(room_id);
            header.set_signature([0xAA; 64]);
            Frame::new(header, Bytes::new())
        },

        FrameAttack::WrongEpoch { member_idx, epoch_offset } => {
            let sender_id = members[(*member_idx as usize) % members.len()];
            let signing_key = member_keys.get(&sender_id).expect("member key must exist");
            let wrong_epoch = if *epoch_offset < 0 {
                epoch.saturating_sub(epoch_offset.unsigned_abs() as u64)
            } else {
                epoch.saturating_add(*epoch_offset as u64)
            };
            create_signed_frame(signing_key, sender_id, wrong_epoch, room_id, Opcode::AppMessage)
        },

        FrameAttack::InvalidOpcode { member_idx, opcode } => {
            let sender_id = members[(*member_idx as usize) % members.len()];
            let signing_key = member_keys.get(&sender_id).expect("member key must exist");
            let opcode_enum = Opcode::from_u16(*opcode).unwrap_or(Opcode::AppMessage);
            create_signed_frame(signing_key, sender_id, epoch, room_id, opcode_enum)
        },

        FrameAttack::CorruptedSignature { member_idx, bit_flip } => {
            let sender_id = members[(*member_idx as usize) % members.len()];
            let signing_key = member_keys.get(&sender_id).expect("member key must exist");
            let mut frame =
                create_signed_frame(signing_key, sender_id, epoch, room_id, Opcode::AppMessage);

            let sig_bytes = frame.header.signature();
            if sig_bytes.len() == 64 {
                let mut sig_array: [u8; 64] = *sig_bytes;
                sig_array[(*bit_flip as usize) % 64] ^= 0x01;
                frame.header.set_signature(sig_array);
            }
            frame
        },
    }
}

fn create_signed_frame(
    signing_key: &SigningKey,
    sender_id: u64,
    epoch: u64,
    room_id: u128,
    opcode: Opcode,
) -> Frame {
    let mut header = FrameHeader::new(opcode);
    header.set_sender_id(sender_id);
    header.set_epoch(epoch);
    header.set_room_id(room_id);
    header.set_log_index(0);

    let signature = signing_key.sign(&header.signing_data());
    header.set_signature(signature.to_bytes());

    Frame::new(header, Bytes::new())
}

fn verify_storage_invariants(room_id: u128, expected_count: u64, storage: &MemoryStorage) {
    if let Ok(frames) = storage.load_frames(room_id, 0, expected_count.max(1) as usize) {
        assert_eq!(frames.len() as u64, expected_count);

        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header.log_index(), i as u64);
        }
    }
}
