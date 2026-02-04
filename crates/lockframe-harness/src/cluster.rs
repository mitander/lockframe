//! Test cluster simulation for convergence testing.
//!
//! Provides a simplified server implementation that stores `GroupInfo` and
//! broadcasts commits. This allows deterministic property-based testing
//! of Client convergence logic without requiring a real async server.

use std::collections::HashMap;

use lockframe_client::{Client, ClientAction, ClientEvent, ClientIdentity};
use lockframe_core::mls::RoomId;
use lockframe_proto::{FrameHeader, Opcode, Payload, payloads::mls::GroupInfoPayload};

use crate::SimEnv;

/// Simulated cluster of clients with minimal server-side `GroupInfo` storage.
pub struct TestCluster {
    /// List of simulated clients.
    pub clients: Vec<Client<SimEnv>>,
    /// Simulated server storage: `room_id` -> (epoch, `group_info_bytes`)
    group_info_storage: HashMap<RoomId, (u64, Vec<u8>)>,
}

impl TestCluster {
    /// Create a new test cluster with the specified number of clients.
    pub fn new(seed: u64, num_clients: usize) -> Self {
        let env = SimEnv::with_seed(seed);
        let clients = (0..num_clients)
            .map(|i| {
                let sender_id = (i + 1) as u64;
                let identity = ClientIdentity::new(sender_id);
                Client::new(env.clone(), identity)
            })
            .collect();

        Self { clients, group_info_storage: HashMap::new() }
    }

    /// Store `GroupInfo` for a room (simulates server's Storage trait).
    pub fn store_group_info(&mut self, room_id: RoomId, epoch: u64, group_info_bytes: Vec<u8>) {
        self.group_info_storage.insert(room_id, (epoch, group_info_bytes));
    }

    /// Load `GroupInfo` for a room (simulates server's Storage trait).
    pub fn load_group_info(&self, room_id: RoomId) -> Option<(u64, Vec<u8>)> {
        self.group_info_storage.get(&room_id).cloned()
    }

    /// Get epochs for all room members.
    pub fn epochs(&self, room_id: RoomId) -> Vec<(usize, u64)> {
        self.clients
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.epoch(room_id).map(|e| (i, e)))
            .collect()
    }

    /// Create a room using the first client.
    pub fn create_room(&mut self, room_id: RoomId) -> Result<(), String> {
        let actions = self.clients[0]
            .handle(ClientEvent::CreateRoom { room_id })
            .map_err(|e| format!("create room failed: {e}"))?;

        for action in &actions {
            if let ClientAction::Send(frame) = action
                && frame.header.opcode_enum() == Some(Opcode::GroupInfo)
                && let Ok(Payload::GroupInfo(payload)) = Payload::from_frame(frame)
            {
                self.store_group_info(room_id, payload.epoch, payload.group_info_bytes);
            }
        }

        Ok(())
    }

    /// Add a client via Welcome (existing member adds them).
    pub fn join_via_welcome(&mut self, room_id: RoomId, joiner_idx: usize) -> Result<(), String> {
        let (kp_bytes, _) = self.clients[joiner_idx]
            .generate_key_package()
            .map_err(|e| format!("keygen failed: {e}"))?;

        let add_actions = self.clients[0]
            .handle(ClientEvent::AddMembers { room_id, key_packages: vec![kp_bytes] })
            .map_err(|e| format!("add member failed: {e}"))?;

        let mut welcome_frame = None;
        let mut commit_frame = None;

        for action in &add_actions {
            if let ClientAction::Send(frame) = action {
                match frame.header.opcode_enum() {
                    Some(Opcode::Welcome) => welcome_frame = Some(frame),
                    Some(Opcode::Commit) => commit_frame = Some(frame),
                    _ => {},
                }
            }
        }

        let welcome = welcome_frame.ok_or("no Welcome frame")?;
        let commit = commit_frame.ok_or("no Commit frame")?;

        let commit_actions = self.clients[0]
            .handle(ClientEvent::FrameReceived(commit.clone()))
            .map_err(|e| format!("creator commit failed: {e}"))?;

        // Store GroupInfo published AFTER commit merge
        for action in &commit_actions {
            if let ClientAction::Send(frame) = action
                && frame.header.opcode_enum() == Some(Opcode::GroupInfo)
                && let Ok(Payload::GroupInfo(payload)) = Payload::from_frame(frame)
            {
                {
                    self.store_group_info(room_id, payload.epoch, payload.group_info_bytes);
                }
            }
        }

        self.clients[joiner_idx]
            .handle(ClientEvent::JoinRoom { room_id, welcome: welcome.payload.to_vec() })
            .map_err(|e| format!("join via welcome failed: {e}"))?;

        for (i, client) in self.clients.iter_mut().enumerate() {
            if i == 0 || i == joiner_idx {
                continue;
            }
            if client.is_member(room_id) {
                let _ = client.handle(ClientEvent::FrameReceived(commit.clone()));
            }
        }

        Ok(())
    }

    /// Add a client via external commit.
    pub fn join_via_external(&mut self, room_id: RoomId, joiner_idx: usize) -> Result<(), String> {
        let (epoch, group_info_bytes) =
            self.load_group_info(room_id).ok_or("no GroupInfo stored for room")?;

        self.clients[joiner_idx]
            .handle(ClientEvent::ExternalJoin { room_id })
            .map_err(|e| format!("external join init failed: {e}"))?;

        let payload = GroupInfoPayload { room_id, epoch, group_info_bytes };
        let gi_frame = Payload::GroupInfo(payload)
            .into_frame(FrameHeader::new(Opcode::GroupInfo))
            .map_err(|e| format!("GroupInfo frame failed: {e}"))?;

        let join_actions = self.clients[joiner_idx]
            .handle(ClientEvent::FrameReceived(gi_frame))
            .map_err(|e| format!("process GroupInfo failed: {e}"))?;

        let mut ext_commit = None;

        for action in &join_actions {
            if let ClientAction::Send(frame) = action
                && matches!(
                    frame.header.opcode_enum(),
                    Some(Opcode::Commit | Opcode::ExternalCommit)
                )
            {
                ext_commit = Some(frame);
            }
        }

        let commit = ext_commit.ok_or("no external commit frame")?;
        let mut joiner_group_info = None;

        for (i, client) in self.clients.iter_mut().enumerate() {
            if client.is_member(room_id) || i == joiner_idx {
                let commit_actions =
                    client.handle(ClientEvent::FrameReceived(commit.clone())).unwrap_or_default();

                // Capture GroupInfo published AFTER commit merge
                for action in &commit_actions {
                    if let ClientAction::Send(frame) = action
                        && frame.header.opcode_enum() == Some(Opcode::GroupInfo)
                        && let Ok(Payload::GroupInfo(payload)) = Payload::from_frame(frame)
                    {
                        joiner_group_info = Some((payload.epoch, payload.group_info_bytes));
                    }
                }
            }
        }

        if let Some((epoch, group_info_bytes)) = joiner_group_info {
            self.store_group_info(room_id, epoch, group_info_bytes);
        }

        Ok(())
    }

    /// Send message and verify delivery.
    pub fn send_and_verify(
        &mut self,
        room_id: RoomId,
        sender_idx: usize,
        message: &[u8],
    ) -> Result<(), String> {
        let sender_id = self.clients[sender_idx].sender_id();

        let send_actions = self.clients[sender_idx]
            .handle(ClientEvent::SendMessage { room_id, plaintext: message.to_vec() })
            .map_err(|e| format!("send failed: {e}"))?;

        let mut msg_frame = None;
        for action in send_actions {
            if let ClientAction::Send(frame) = action
                && frame.header.opcode_enum() == Some(Opcode::AppMessage)
            {
                msg_frame = Some(frame);
                break;
            }
        }

        let msg_frame = msg_frame.ok_or("no AppMessage frame")?;

        for (i, client) in self.clients.iter_mut().enumerate() {
            if i == sender_idx || !client.is_member(room_id) {
                // Ignore sender
                continue;
            }

            let recv_actions = client
                .handle(ClientEvent::FrameReceived(msg_frame.clone()))
                .map_err(|e| format!("client {i} receive failed: {e}"))?;

            let delivered = recv_actions.iter().any(|a| {
                matches!(a, ClientAction::DeliverMessage { sender_id: s, plaintext, .. }
                    if *s == sender_id && plaintext == message)
            });

            if !delivered {
                return Err(format!("client {i} did not receive message"));
            }
        }

        Ok(())
    }
}
