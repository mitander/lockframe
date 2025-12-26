//! Fuzz target for Sequencer state machine
//!
//! Ensure log index monotonicity and room isolation (HIGH priority)
//!
//! # Strategy
//!
//! - Multi-room: Create and process frames across multiple rooms
//! - Room boundaries: room_id = 0 (invalid), small values, u128::MAX
//! - Frame types: Valid frames, epoch overflow
//! - Index verification: Check storage matches expected state
//!
//! # Invariants
//!
//! - Log index strictly monotonic per room (never decreases)
//! - Different rooms have independent log index sequences
//! - Room 0 (invalid) MUST reject

#![no_main]

use std::collections::HashMap;

use arbitrary::Arbitrary;
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use lockframe_proto::{Frame, FrameHeader, Opcode};
use lockframe_server::{
    sequencer::{Sequencer, SequencerAction},
    storage::MemoryStorage,
    Storage,
};

#[derive(Debug, Clone, Arbitrary)]
enum SequencerOp {
    ProcessFrame { room_id: RoomIdChoice, frame_type: FrameType },
    CheckLogIndex { room_id: RoomIdChoice },
}

#[derive(Debug, Clone, Arbitrary)]
enum RoomIdChoice {
    Zero,
    Small(u8),
    MaxU128,
}

#[derive(Debug, Clone, Arbitrary)]
enum FrameType {
    Valid { opcode: u16, epoch: u8 },
    EpochOverflow,
}

fuzz_target!(|ops: Vec<SequencerOp>| {
    let mut sequencer = Sequencer::new();
    let storage = MemoryStorage::new();
    let mut expected_indices: HashMap<u128, u64> = HashMap::new();

    for op in ops {
        match op {
            SequencerOp::ProcessFrame { room_id, frame_type } => {
                let room_id_value = get_room_id(&room_id);
                let frame = create_frame(&frame_type, room_id_value);

                match sequencer.process_frame(frame.clone(), &storage) {
                    Ok(actions) => {
                        if room_id_value == 0 {
                            panic!("Sequencer accepted frame with room_id = 0!");
                        }
                        if !matches!(frame_type, FrameType::Valid { .. }) {
                            panic!("Sequencer accepted invalid frame type: {:?}", frame_type);
                        }

                        for action in actions {
                            match action {
                                SequencerAction::AcceptFrame { room_id: action_room, log_index, .. } => {
                                    assert_eq!(action_room, room_id_value);
                                    let expected = expected_indices.entry(room_id_value).or_insert(0);
                                    assert_eq!(log_index, *expected);
                                    *expected += 1;
                                }
                                SequencerAction::RejectFrame { .. } => {
                                    panic!("RejectFrame action in Ok result!");
                                }
                                SequencerAction::StoreFrame { room_id: action_room, log_index, frame } => {
                                    assert_eq!(action_room, room_id_value);
                                    let _ = storage.store_frame(action_room, log_index, &frame);
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => {}
                }
            }

            SequencerOp::CheckLogIndex { room_id } => {
                let room_id_value = get_room_id(&room_id);

                match storage.latest_log_index(room_id_value) {
                    Ok(Some(latest)) => {
                        let expected = expected_indices.get(&room_id_value).copied().unwrap_or(0);
                        if expected > 0 {
                            assert_eq!(latest, expected - 1);
                        }
                    }
                    Ok(None) => {
                        let expected = expected_indices.get(&room_id_value).copied().unwrap_or(0);
                        assert_eq!(expected, 0);
                    }
                    Err(_) => {}
                }
            }
        }
    }

    for (room_id, expected_count) in &expected_indices {
        verify_sequential_indices(*room_id, *expected_count, &storage);
    }
});

fn get_room_id(choice: &RoomIdChoice) -> u128 {
    match choice {
        RoomIdChoice::Zero => 0,
        RoomIdChoice::Small(v) => (*v as u128).max(1).min(10),
        RoomIdChoice::MaxU128 => u128::MAX,
    }
}

fn create_frame(frame_type: &FrameType, room_id: u128) -> Frame {
    match frame_type {
        FrameType::Valid { opcode, epoch } => {
            let opcode_enum = Opcode::from_u16(*opcode).unwrap_or(Opcode::AppMessage);
            let mut header = FrameHeader::new(opcode_enum);
            header.set_room_id(room_id);
            header.set_epoch(*epoch as u64);
            header.set_sender_id(100);
            if opcode_enum != Opcode::Welcome {
                header.set_log_index(0);
            }
            Frame::new(header, Bytes::new())
        }
        FrameType::EpochOverflow => {
            let mut header = FrameHeader::new(Opcode::AppMessage);
            header.set_room_id(room_id);
            header.set_epoch(u64::MAX);
            header.set_sender_id(100);
            Frame::new(header, Bytes::new())
        }
    }
}

fn verify_sequential_indices(room_id: u128, expected_count: u64, storage: &MemoryStorage) {
    let limit = expected_count.max(1) as usize;
    if let Ok(frames) = storage.load_frames(room_id, 0, limit) {
        assert_eq!(frames.len() as u64, expected_count);

        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header.log_index(), i as u64);
        }
    }
}
