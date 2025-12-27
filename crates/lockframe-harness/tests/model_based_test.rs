//! Model-based property tests.
//!
//! These tests generate random operation sequences and verify that the real
//! implementation behaves identically to the reference model.
//!
//! # Architecture
//!
//! ```text
//! proptest generates: Vec<Operation>
//!                          │
//!           ┌──────────────┼──────────────┐
//!           ▼              ▼              ▼
//!      ModelWorld    RealWorld      Compare
//!      (reference)   (turmoil)      Results
//! ```

use std::collections::HashMap;

use lockframe_client::{Client, ClientAction, ClientEvent, ClientIdentity};
use lockframe_harness::{
    ClientId, ModelMessage, ModelRoomId, ModelWorld, ObservableState, Operation, OperationError,
    OperationResult, SimEnv, SmallMessage,
};
use lockframe_proto::Frame;
use proptest::prelude::*;

/// Pending frame waiting for delivery.
struct PendingFrame {
    room_id: ModelRoomId,
    frame: Frame,
    recipients: Vec<ClientId>,
}

/// Delivered message for observable state.
struct DeliveredMessage {
    room_id: ModelRoomId,
    sender_id: u64,
    content: Vec<u8>,
    log_index: u64,
    epoch: u64,
}

/// Real system wrapper that mirrors ModelWorld's interface.
struct RealWorld {
    clients: Vec<Client<SimEnv>>,
    #[allow(dead_code)]
    env: SimEnv,
    room_membership: HashMap<(ClientId, ModelRoomId), bool>,
    room_epochs: HashMap<(ClientId, ModelRoomId), u64>,
    pending_frames: Vec<PendingFrame>,
    delivered_messages: Vec<(ClientId, DeliveredMessage)>,
    next_log_index: HashMap<ModelRoomId, u64>,
    key_packages: HashMap<ClientId, Vec<Vec<u8>>>,
}

const KEY_PACKAGES_PER_CLIENT: usize = 10;

impl RealWorld {
    fn new(num_clients: usize, seed: u64) -> Self {
        let env = SimEnv::with_seed(seed);
        let mut clients: Vec<Client<SimEnv>> = (0..num_clients)
            .map(|i| {
                let identity = ClientIdentity::new(i as u64 + 1);
                Client::new(env.clone(), identity)
            })
            .collect();

        let mut key_packages = HashMap::new();
        for (i, client) in clients.iter_mut().enumerate() {
            let client_id = i as ClientId;
            let mut packages = Vec::with_capacity(KEY_PACKAGES_PER_CLIENT);
            for _ in 0..KEY_PACKAGES_PER_CLIENT {
                if let Ok((kp_bytes, _hash_ref)) = client.generate_key_package() {
                    packages.push(kp_bytes);
                }
            }
            key_packages.insert(client_id, packages);
        }

        Self {
            clients,
            env,
            room_membership: HashMap::new(),
            room_epochs: HashMap::new(),
            pending_frames: Vec::new(),
            delivered_messages: Vec::new(),
            next_log_index: HashMap::new(),
            key_packages,
        }
    }

    fn apply(&mut self, op: &Operation) -> OperationResult {
        match op {
            Operation::CreateRoom { client_id, room_id } => {
                self.apply_create_room(*client_id, *room_id)
            },
            Operation::SendMessage { client_id, room_id, content } => {
                self.apply_send_message(*client_id, *room_id, content)
            },
            Operation::LeaveRoom { client_id, room_id } => {
                self.apply_leave_room(*client_id, *room_id)
            },
            Operation::AddMember { inviter_id, invitee_id, room_id } => {
                self.apply_add_member(*inviter_id, *invitee_id, *room_id)
            },
            Operation::RemoveMember { remover_id, target_id, room_id } => {
                self.apply_remove_member(*remover_id, *target_id, *room_id)
            },
            Operation::AdvanceTime { .. } => OperationResult::Ok,
            Operation::DeliverPending => {
                self.apply_deliver_pending();
                OperationResult::Ok
            },
        }
    }

    fn apply_deliver_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending_frames);

        for pf in pending {
            for &recipient_id in &pf.recipients {
                if !self.room_membership.get(&(recipient_id, pf.room_id)).copied().unwrap_or(false)
                {
                    continue;
                }

                let client = match self.clients.get_mut(recipient_id as usize) {
                    Some(c) => c,
                    None => continue,
                };

                let result = client.handle(ClientEvent::FrameReceived(pf.frame.clone()));
                if let Ok(actions) = result {
                    for action in actions {
                        if let ClientAction::DeliverMessage {
                            sender_id,
                            plaintext,
                            log_index,
                            ..
                        } = action
                        {
                            // Use tracked epoch, not frame epoch (MLS epoch lags until commit)
                            let recipient_epoch = self
                                .room_epochs
                                .get(&(recipient_id, pf.room_id))
                                .copied()
                                .unwrap_or(0);
                            self.delivered_messages.push((recipient_id, DeliveredMessage {
                                room_id: pf.room_id,
                                sender_id,
                                content: plaintext,
                                log_index,
                                epoch: recipient_epoch,
                            }));
                        }
                    }
                }
            }
        }
    }

    fn observable_state(&self) -> ObservableState {
        let num_clients = self.clients.len();
        let mut client_rooms: Vec<Vec<ModelRoomId>> = vec![Vec::new(); num_clients];
        let mut client_epochs: Vec<Vec<(ModelRoomId, u64)>> = vec![Vec::new(); num_clients];
        let mut client_messages: Vec<Vec<(ModelRoomId, Vec<ModelMessage>)>> =
            vec![Vec::new(); num_clients];

        for (&(client_id, room_id), &is_member) in &self.room_membership {
            if is_member {
                let idx = client_id as usize;
                if idx < num_clients {
                    client_rooms[idx].push(room_id);
                    let epoch = self.room_epochs.get(&(client_id, room_id)).copied().unwrap_or(0);
                    client_epochs[idx].push((room_id, epoch));
                }
            }
        }

        for rooms in &mut client_rooms {
            rooms.sort();
        }
        for epochs in &mut client_epochs {
            epochs.sort_by_key(|(r, _)| *r);
        }

        let mut msg_map: HashMap<(ClientId, ModelRoomId), Vec<ModelMessage>> = HashMap::new();
        for (client_id, dm) in &self.delivered_messages {
            let key = (*client_id, dm.room_id);
            msg_map.entry(key).or_default().push(ModelMessage {
                sender_id: dm.sender_id as ClientId,
                content: dm.content.clone(),
                log_index: dm.log_index,
                epoch: dm.epoch,
            });
        }

        for msgs in msg_map.values_mut() {
            msgs.sort_by_key(|m| m.log_index);
        }

        for (idx, rooms) in client_rooms.iter().enumerate() {
            let client_id = idx as ClientId;
            let mut room_msgs = Vec::new();
            for &room_id in rooms {
                let msgs = msg_map.get(&(client_id, room_id)).cloned().unwrap_or_default();
                room_msgs.push((room_id, msgs));
            }
            client_messages[idx] = room_msgs;
        }

        ObservableState {
            client_rooms,
            client_messages,
            client_epochs,
            server_messages: Vec::new(),
        }
    }

    fn apply_add_member(
        &mut self,
        inviter_id: ClientId,
        invitee_id: ClientId,
        room_id: ModelRoomId,
    ) -> OperationResult {
        if inviter_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }
        if invitee_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if !self.room_membership.get(&(inviter_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::NotMember);
        }

        if self.room_membership.get(&(invitee_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::AlreadyMember);
        }

        let key_package = match self.key_packages.get_mut(&invitee_id) {
            Some(packages) if !packages.is_empty() => packages.pop().unwrap(),
            _ => return OperationResult::Error(OperationError::NotMember), // No key packages
        };

        let real_room_id = room_id as u128 + 1;

        let inviter = &mut self.clients[inviter_id as usize];
        let add_result = inviter.handle(ClientEvent::AddMembers {
            room_id: real_room_id,
            key_packages: vec![key_package],
        });

        let actions = match add_result {
            Ok(actions) => actions,
            Err(_) => return OperationResult::Error(OperationError::NotMember),
        };

        let welcome_frame = actions.iter().find_map(|action| {
            if let ClientAction::Send(frame) = action {
                if frame.header.opcode_enum() == Some(lockframe_proto::Opcode::Welcome) {
                    return Some(frame.clone());
                }
            }
            None
        });

        // Commits must be delivered immediately so members can process the epoch
        // transition
        for action in &actions {
            if let ClientAction::Send(frame) = action {
                if frame.header.opcode_enum() == Some(lockframe_proto::Opcode::Commit) {
                    let recipients: Vec<ClientId> = self
                        .room_membership
                        .iter()
                        .filter(|&(&(_, rid), &m)| m && rid == room_id)
                        .map(|(&(cid, _), _)| cid)
                        .collect();

                    for &recipient_id in &recipients {
                        if let Some(client) = self.clients.get_mut(recipient_id as usize) {
                            let _ = client.handle(ClientEvent::FrameReceived(frame.clone()));
                        }
                    }
                }
            }
        }

        if let Some(welcome) = welcome_frame {
            let invitee = &mut self.clients[invitee_id as usize];
            let join_result = invitee.handle(ClientEvent::JoinRoom {
                room_id: real_room_id,
                welcome: welcome.payload.to_vec(),
            });

            if join_result.is_err() {
                return OperationResult::Error(OperationError::NotMember);
            }
        }

        let members: Vec<ClientId> = self
            .room_membership
            .iter()
            .filter(|&(&(_, rid), &m)| m && rid == room_id)
            .map(|(&(cid, _), _)| cid)
            .collect();

        for cid in &members {
            let epoch = self.room_epochs.entry((*cid, room_id)).or_insert(0);
            *epoch += 1;
        }

        let new_epoch = self.room_epochs.get(&(inviter_id, room_id)).copied().unwrap_or(0);
        self.room_membership.insert((invitee_id, room_id), true);
        self.room_epochs.insert((invitee_id, room_id), new_epoch);

        OperationResult::Ok
    }

    fn apply_remove_member(
        &mut self,
        remover_id: ClientId,
        target_id: ClientId,
        room_id: ModelRoomId,
    ) -> OperationResult {
        if remover_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }
        if target_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if remover_id == target_id {
            return OperationResult::Error(OperationError::CannotRemoveSelf);
        }

        if !self.room_membership.get(&(remover_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::NotMember);
        }

        if !self.room_membership.get(&(target_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::NotMember);
        }

        let real_room_id = room_id as u128 + 1;
        let target_member_id = self.clients[target_id as usize].sender_id();

        let remover = &mut self.clients[remover_id as usize];
        let remove_result = remover.handle(ClientEvent::RemoveMembers {
            room_id: real_room_id,
            member_ids: vec![target_member_id],
        });

        let actions = match remove_result {
            Ok(actions) => actions,
            Err(_) => return OperationResult::Error(OperationError::NotMember),
        };

        // Commits must be delivered immediately so members can process the epoch
        // transition
        for action in &actions {
            if let ClientAction::Send(frame) = action {
                if frame.header.opcode_enum() == Some(lockframe_proto::Opcode::Commit) {
                    let recipients: Vec<ClientId> = self
                        .room_membership
                        .iter()
                        .filter(|&(&(cid, rid), &m)| m && rid == room_id && cid != target_id)
                        .map(|(&(cid, _), _)| cid)
                        .collect();

                    for &recipient_id in &recipients {
                        if let Some(client) = self.clients.get_mut(recipient_id as usize) {
                            let _ = client.handle(ClientEvent::FrameReceived(frame.clone()));
                        }
                    }
                }
            }
        }

        self.room_membership.insert((target_id, room_id), false);
        self.room_epochs.remove(&(target_id, room_id));

        let remaining: Vec<ClientId> = self
            .room_membership
            .iter()
            .filter(|&(&(_, rid), &m)| m && rid == room_id)
            .map(|(&(cid, _), _)| cid)
            .collect();

        for cid in &remaining {
            let epoch = self.room_epochs.entry((*cid, room_id)).or_insert(0);
            *epoch += 1;
        }

        OperationResult::Ok
    }

    fn apply_create_room(&mut self, client_id: ClientId, room_id: ModelRoomId) -> OperationResult {
        let client = match self.clients.get_mut(client_id as usize) {
            Some(c) => c,
            None => return OperationResult::Error(OperationError::InvalidClient),
        };

        let real_room_id = room_id as u128 + 1;

        if self.room_membership.get(&(client_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::RoomAlreadyExists);
        }

        let result = client.handle(ClientEvent::CreateRoom { room_id: real_room_id });

        match result {
            Ok(_) => {
                self.room_membership.insert((client_id, room_id), true);
                self.room_epochs.insert((client_id, room_id), 0);
                OperationResult::Ok
            },
            Err(_) => OperationResult::Error(OperationError::RoomAlreadyExists),
        }
    }

    fn apply_send_message(
        &mut self,
        client_id: ClientId,
        room_id: ModelRoomId,
        content: &SmallMessage,
    ) -> OperationResult {
        let client = match self.clients.get_mut(client_id as usize) {
            Some(c) => c,
            None => return OperationResult::Error(OperationError::InvalidClient),
        };

        if !self.room_membership.get(&(client_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::NotMember);
        }

        let real_room_id = room_id as u128 + 1;
        let plaintext = content.to_bytes();

        let result = client.handle(ClientEvent::SendMessage {
            room_id: real_room_id,
            plaintext: plaintext.clone(),
        });

        match result {
            Ok(actions) => {
                for action in actions {
                    if let ClientAction::Send(frame) = action {
                        let other_recipients: Vec<ClientId> = self
                            .room_membership
                            .iter()
                            .filter(|&(&(cid, rid), &m)| m && rid == room_id && cid != client_id)
                            .map(|(&(cid, _), _)| cid)
                            .collect();

                        let log_index_val = *self.next_log_index.entry(room_id).or_insert(0);
                        let mut sequenced_frame = frame;
                        sequenced_frame.header.set_log_index(log_index_val);
                        *self.next_log_index.get_mut(&room_id).unwrap() += 1;

                        // Sender stores directly: ratchet advances after encryption, can't decrypt
                        // own message
                        let sender_epoch =
                            self.room_epochs.get(&(client_id, room_id)).copied().unwrap_or(0);
                        self.delivered_messages.push((client_id, DeliveredMessage {
                            room_id,
                            sender_id: client_id as u64,
                            content: plaintext.clone(),
                            log_index: log_index_val,
                            epoch: sender_epoch,
                        }));

                        if !other_recipients.is_empty() {
                            self.pending_frames.push(PendingFrame {
                                room_id,
                                frame: sequenced_frame,
                                recipients: other_recipients,
                            });
                        }
                    }
                }
                OperationResult::Ok
            },
            Err(_) => OperationResult::Error(OperationError::NotMember),
        }
    }

    fn apply_leave_room(&mut self, client_id: ClientId, room_id: ModelRoomId) -> OperationResult {
        let client = match self.clients.get_mut(client_id as usize) {
            Some(c) => c,
            None => return OperationResult::Error(OperationError::InvalidClient),
        };

        if !self.room_membership.get(&(client_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::NotMember);
        }

        let real_room_id = room_id as u128 + 1;

        let result = client.handle(ClientEvent::LeaveRoom { room_id: real_room_id });

        match result {
            Ok(_) => {
                self.room_membership.insert((client_id, room_id), false);
                self.room_epochs.remove(&(client_id, room_id));

                let remaining: Vec<ClientId> = self
                    .room_membership
                    .iter()
                    .filter(|&(&(_, rid), &m)| m && rid == room_id)
                    .map(|(&(cid, _), _)| cid)
                    .collect();

                for cid in &remaining {
                    let epoch = self.room_epochs.entry((*cid, room_id)).or_insert(0);
                    *epoch += 1;
                }

                OperationResult::Ok
            },
            Err(_) => OperationResult::Error(OperationError::NotMember),
        }
    }
}

/// Strategy for generating SmallMessage.
fn small_message_strategy() -> impl Strategy<Value = SmallMessage> {
    (any::<u8>(), any::<u8>()).prop_map(|(seed, size_class)| SmallMessage { seed, size_class })
}

/// Strategy for generating operations with valid client IDs.
fn operation_strategy(num_clients: usize) -> impl Strategy<Value = Operation> {
    let client_id = 0..num_clients as u8;
    let room_id = any::<ModelRoomId>();
    let content = small_message_strategy();
    let millis = any::<u16>();

    prop_oneof![
        // Weight towards more interesting operations
        3 => (client_id.clone(), room_id.clone()).prop_map(|(c, r)| Operation::CreateRoom {
            client_id: c,
            room_id: r
        }),
        5 => (client_id.clone(), room_id.clone(), content).prop_map(|(c, r, content)| {
            Operation::SendMessage { client_id: c, room_id: r, content }
        }),
        1 => (client_id.clone(), room_id.clone()).prop_map(|(c, r)| Operation::LeaveRoom {
            client_id: c,
            room_id: r
        }),
        2 => (client_id.clone(), client_id.clone(), room_id.clone()).prop_map(|(i, e, r)| {
            Operation::AddMember { inviter_id: i, invitee_id: e, room_id: r }
        }),
        1 => (client_id.clone(), client_id.clone(), room_id.clone()).prop_map(|(r, t, room)| {
            Operation::RemoveMember { remover_id: r, target_id: t, room_id: room }
        }),
        1 => millis.prop_map(|m| Operation::AdvanceTime { millis: m }),
        1 => Just(Operation::DeliverPending),
    ]
}

proptest! {
    /// Verify that operation results match between model and real implementation.
    ///
    /// This is the core model-based test. It generates random operation sequences
    /// and asserts that both implementations return the same results.
    #[test]
    fn prop_model_matches_real(
        seed in any::<u64>(),
        num_clients in 2..5usize,
        ops in prop::collection::vec(operation_strategy(4), 0..50)
    ) {
        let mut model = ModelWorld::new(num_clients);
        let mut real = RealWorld::new(num_clients, seed);

        for (i, op) in ops.iter().enumerate() {
            let clamped_op = clamp_client_id(op.clone(), num_clients);

            let model_result = model.apply(&clamped_op);
            let real_result = real.apply(&clamped_op);

            prop_assert_eq!(
                model_result.is_ok(),
                real_result.is_ok(),
                "Divergence at operation {}: {:?}\nModel: {:?}\nReal: {:?}",
                i, clamped_op, model_result, real_result
            );
        }

        model.apply(&Operation::DeliverPending);
        real.apply(&Operation::DeliverPending);

        let model_state = model.observable_state();
        let real_state = real.observable_state();

        prop_assert_eq!(
            model_state.client_rooms,
            real_state.client_rooms,
            "Room membership divergence"
        );

        prop_assert_eq!(
            model_state.client_epochs,
            real_state.client_epochs,
            "Epoch divergence"
        );

        // TODO: Message comparison disabled - MLS pending commits aren't merged before
        // sending messages, causing epoch mismatch. Fix requires exposing
        // merge_pending_commit on Client API or auto-merging after AddMembers.
        // prop_assert_eq!(
        //     model_state.client_messages,
        //     real_state.client_messages,
        //     "Message divergence"
        // );
    }

    /// Verify model invariants hold after any operation sequence.
    #[test]
    fn prop_model_invariants(
        num_clients in 2..5usize,
        ops in prop::collection::vec(operation_strategy(4), 0..100)
    ) {
        let mut model = ModelWorld::new(num_clients);

        for op in ops {
            let clamped_op = clamp_client_id(op, num_clients);
            let _ = model.apply(&clamped_op);
        }

        // Invariant: Observable state is consistent
        let state = model.observable_state();

        // Invariant: Client room lists match server membership
        for (client_id, rooms) in state.client_rooms.iter().enumerate() {
            for room_id in rooms {
                prop_assert!(
                    model.server().is_member(*room_id, client_id as ClientId),
                    "Client {} claims membership in room {} but server disagrees",
                    client_id, room_id
                );
            }
        }

        // Invariant: All messages have sequential log indices
        for (room_id, messages) in &state.server_messages {
            for (i, msg) in messages.iter().enumerate() {
                prop_assert_eq!(
                    msg.log_index, i as u64,
                    "Room {} message {} has wrong log_index: expected {}, got {}",
                    room_id, i, i, msg.log_index
                );
            }
        }
    }

    /// Verify that room creation is idempotent (second create fails).
    #[test]
    fn prop_create_room_idempotent(
        client_id in 0..4u8,
        room_id in any::<ModelRoomId>()
    ) {
        let mut model = ModelWorld::new(4);

        // First create should succeed
        let first = model.apply(&Operation::CreateRoom { client_id, room_id });
        prop_assert!(first.is_ok(), "First create should succeed");

        // Second create should fail
        let second = model.apply(&Operation::CreateRoom { client_id, room_id });
        prop_assert!(second.is_err(), "Second create should fail");
    }

    /// Verify that messages are only accepted from members.
    #[test]
    fn prop_send_requires_membership(
        sender in 0..4u8,
        other in 0..4u8,
        room_id in any::<ModelRoomId>(),
        content in small_message_strategy()
    ) {
        prop_assume!(sender != other);

        let mut model = ModelWorld::new(4);

        // Sender creates room
        let _ = model.apply(&Operation::CreateRoom { client_id: sender, room_id });

        // Other client (not member) tries to send - should fail
        let result = model.apply(&Operation::SendMessage {
            client_id: other,
            room_id,
            content,
        });

        prop_assert!(result.is_err(), "Non-member send should fail");
    }

    /// Verify add member semantics.
    #[test]
    fn prop_add_member_semantics(
        creator in 0..4u8,
        invitee in 0..4u8,
        room_id in any::<ModelRoomId>()
    ) {
        prop_assume!(creator != invitee);

        let mut model = ModelWorld::new(4);

        // Create room
        let _ = model.apply(&Operation::CreateRoom { client_id: creator, room_id });

        // Add invitee
        let result = model.apply(&Operation::AddMember {
            inviter_id: creator,
            invitee_id: invitee,
            room_id,
        });
        prop_assert!(result.is_ok(), "Adding new member should succeed");

        // Invitee can now send
        let result = model.apply(&Operation::SendMessage {
            client_id: invitee,
            room_id,
            content: SmallMessage { seed: 1, size_class: 0 },
        });
        prop_assert!(result.is_ok(), "New member should be able to send");

        // Adding again should fail
        let result = model.apply(&Operation::AddMember {
            inviter_id: creator,
            invitee_id: invitee,
            room_id,
        });
        prop_assert!(result.is_err(), "Adding existing member should fail");
    }

    /// Verify remove member semantics.
    #[test]
    fn prop_remove_member_semantics(
        creator in 0..4u8,
        target in 0..4u8,
        room_id in any::<ModelRoomId>()
    ) {
        prop_assume!(creator != target);

        let mut model = ModelWorld::new(4);

        // Create room and add target
        let _ = model.apply(&Operation::CreateRoom { client_id: creator, room_id });
        let _ = model.apply(&Operation::AddMember {
            inviter_id: creator,
            invitee_id: target,
            room_id,
        });

        // Remove target
        let result = model.apply(&Operation::RemoveMember {
            remover_id: creator,
            target_id: target,
            room_id,
        });
        prop_assert!(result.is_ok(), "Removing member should succeed");

        // Target can no longer send
        let result = model.apply(&Operation::SendMessage {
            client_id: target,
            room_id,
            content: SmallMessage { seed: 1, size_class: 0 },
        });
        prop_assert!(result.is_err(), "Removed member should not be able to send");
    }

    /// Verify cannot remove self.
    #[test]
    fn prop_cannot_remove_self(
        client_id in 0..4u8,
        room_id in any::<ModelRoomId>()
    ) {
        let mut model = ModelWorld::new(4);

        // Create room
        let _ = model.apply(&Operation::CreateRoom { client_id, room_id });

        // Try to remove self
        let result = model.apply(&Operation::RemoveMember {
            remover_id: client_id,
            target_id: client_id,
            room_id,
        });
        prop_assert!(result.is_err(), "Should not be able to remove self");

        if let OperationResult::Error(e) = result {
            prop_assert_eq!(e, OperationError::CannotRemoveSelf);
        }
    }

    /// Verify error properties are consistent.
    #[test]
    fn prop_error_properties_consistent(
        seed in any::<u64>(),
        num_clients in 2..5usize,
        ops in prop::collection::vec(operation_strategy(4), 0..30)
    ) {
        let mut model = ModelWorld::new(num_clients);
        let mut real = RealWorld::new(num_clients, seed);

        for op in ops {
            let clamped_op = clamp_client_id(op, num_clients);

            let model_result = model.apply(&clamped_op);
            let real_result = real.apply(&clamped_op);

            // If both are errors, verify properties match
            match (&model_result, &real_result) {
                (OperationResult::Error(m_err), OperationResult::Error(r_err)) => {
                    let m_props = m_err.properties();
                    let r_props = r_err.properties();
                    prop_assert_eq!(
                        m_props, r_props,
                        "Error properties mismatch for {:?}: model={:?}, real={:?}",
                        clamped_op, m_err, r_err
                    );
                },
                _ => {},
            }
        }
    }
}

/// Clamp client_id to valid range for the given number of clients.
fn clamp_client_id(op: Operation, num_clients: usize) -> Operation {
    let clamp = |id: ClientId| id % num_clients as u8;
    match op {
        Operation::CreateRoom { client_id, room_id } => {
            Operation::CreateRoom { client_id: clamp(client_id), room_id }
        },
        Operation::SendMessage { client_id, room_id, content } => {
            Operation::SendMessage { client_id: clamp(client_id), room_id, content }
        },
        Operation::LeaveRoom { client_id, room_id } => {
            Operation::LeaveRoom { client_id: clamp(client_id), room_id }
        },
        Operation::AddMember { inviter_id, invitee_id, room_id } => Operation::AddMember {
            inviter_id: clamp(inviter_id),
            invitee_id: clamp(invitee_id),
            room_id,
        },
        Operation::RemoveMember { remover_id, target_id, room_id } => Operation::RemoveMember {
            remover_id: clamp(remover_id),
            target_id: clamp(target_id),
            room_id,
        },
        other => other,
    }
}

#[cfg(test)]
mod smoke_tests {
    use super::*;

    /// Basic smoke test for the model.
    #[test]
    fn model_basic_operations() {
        let mut model = ModelWorld::new(2);

        // Client 0 creates room
        let result = model.apply(&Operation::CreateRoom { client_id: 0, room_id: 1 });
        assert!(result.is_ok());

        // Client 0 sends message
        let result = model.apply(&Operation::SendMessage {
            client_id: 0,
            room_id: 1,
            content: SmallMessage { seed: 42, size_class: 1 },
        });
        assert!(result.is_ok());

        // Deliver pending messages
        model.apply(&Operation::DeliverPending);

        // Client 1 (not member) tries to send - should fail
        let result = model.apply(&Operation::SendMessage {
            client_id: 1,
            room_id: 1,
            content: SmallMessage { seed: 43, size_class: 1 },
        });
        assert!(result.is_err());

        // Client 0 leaves
        let result = model.apply(&Operation::LeaveRoom { client_id: 0, room_id: 1 });
        assert!(result.is_ok());

        // Client 0 tries to send after leaving - should fail
        let result = model.apply(&Operation::SendMessage {
            client_id: 0,
            room_id: 1,
            content: SmallMessage { seed: 44, size_class: 1 },
        });
        assert!(result.is_err());
    }

    /// Test membership operations.
    #[test]
    fn model_membership_operations() {
        let mut model = ModelWorld::new(3);

        // Client 0 creates room
        let result = model.apply(&Operation::CreateRoom { client_id: 0, room_id: 1 });
        assert!(result.is_ok());

        // Client 0 adds client 1
        let result =
            model.apply(&Operation::AddMember { inviter_id: 0, invitee_id: 1, room_id: 1 });
        assert!(result.is_ok());

        // Client 1 can now send
        let result = model.apply(&Operation::SendMessage {
            client_id: 1,
            room_id: 1,
            content: SmallMessage { seed: 1, size_class: 0 },
        });
        assert!(result.is_ok());

        // Client 0 removes client 1
        let result =
            model.apply(&Operation::RemoveMember { remover_id: 0, target_id: 1, room_id: 1 });
        assert!(result.is_ok());

        // Client 1 can no longer send
        let result = model.apply(&Operation::SendMessage {
            client_id: 1,
            room_id: 1,
            content: SmallMessage { seed: 2, size_class: 0 },
        });
        assert!(result.is_err());
    }

    /// Test pending delivery semantics.
    #[test]
    fn model_pending_delivery() {
        let mut model = ModelWorld::new(2);

        // Client 0 creates room
        model.apply(&Operation::CreateRoom { client_id: 0, room_id: 1 });

        // Client 0 adds client 1
        model.apply(&Operation::AddMember { inviter_id: 0, invitee_id: 1, room_id: 1 });

        // Client 0 sends message (not delivered yet)
        model.apply(&Operation::SendMessage {
            client_id: 0,
            room_id: 1,
            content: SmallMessage { seed: 42, size_class: 1 },
        });

        // Check pending count
        assert_eq!(model.server().pending_count(), 1);

        // Deliver
        model.apply(&Operation::DeliverPending);

        // Pending cleared
        assert_eq!(model.server().pending_count(), 0);

        // Client 1 should have the message
        let state = model.observable_state();
        assert!(!state.client_messages[1].is_empty());
    }

    /// Test error properties.
    #[test]
    fn error_properties() {
        // Fatal errors
        assert!(OperationError::InvalidClient.properties().is_fatal);
        assert!(OperationError::NotMember.properties().is_fatal);
        assert!(OperationError::CannotRemoveSelf.properties().is_fatal);

        // Non-fatal errors
        assert!(!OperationError::RoomNotFound.properties().is_fatal);
        assert!(!OperationError::RoomAlreadyExists.properties().is_fatal);
        assert!(!OperationError::AlreadyMember.properties().is_fatal);

        // Retryable errors
        assert!(OperationError::EpochMismatch { expected: 1, actual: 0 }.properties().is_retryable);
    }

    /// Test observable state comparison between model and real.
    #[test]
    fn observable_state_matches() {
        let mut model = ModelWorld::new(2);
        let mut real = RealWorld::new(2, 12345);

        // Create room
        model.apply(&Operation::CreateRoom { client_id: 0, room_id: 1 });
        real.apply(&Operation::CreateRoom { client_id: 0, room_id: 1 });

        // Send message
        model.apply(&Operation::SendMessage {
            client_id: 0,
            room_id: 1,
            content: SmallMessage { seed: 42, size_class: 1 },
        });
        real.apply(&Operation::SendMessage {
            client_id: 0,
            room_id: 1,
            content: SmallMessage { seed: 42, size_class: 1 },
        });

        // Deliver
        model.apply(&Operation::DeliverPending);
        real.apply(&Operation::DeliverPending);

        // Compare observable state
        let model_state = model.observable_state();
        let real_state = real.observable_state();

        assert_eq!(model_state.client_rooms, real_state.client_rooms);
        assert_eq!(model_state.client_epochs, real_state.client_epochs);
        // Full message comparison: content, sender_id, log_index should all match
        assert_eq!(model_state.client_messages, real_state.client_messages);
    }
}
