//! Model-based property tests.
//!
//! These tests generate random operation sequences and verify that the real
//! implementation behaves identically to the reference model.

use std::collections::HashMap;

use lockframe_client::{Client, ClientAction, ClientEvent, ClientIdentity};
use lockframe_harness::{
    ClientId, ModelMessage, ModelRoomId, ModelWorld, ObservableState, Operation, OperationError,
    OperationResult, SimEnv, SmallMessage,
};
use lockframe_proto::{Frame, FrameHeader, Opcode, Payload, payloads::mls::GroupInfoPayload};
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
    room_membership: HashMap<(ClientId, ModelRoomId), bool>,
    room_epochs: HashMap<(ClientId, ModelRoomId), u64>,
    pending_frames: Vec<PendingFrame>,
    delivered_messages: Vec<(ClientId, DeliveredMessage)>,
    next_log_index: HashMap<ModelRoomId, u64>,
    key_packages: HashMap<ClientId, Vec<Vec<u8>>>,
    partitioned: HashMap<ClientId, bool>,
    disconnected: HashMap<ClientId, bool>,
    group_info: HashMap<ModelRoomId, Vec<u8>>,
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
            room_membership: HashMap::new(),
            room_epochs: HashMap::new(),
            pending_frames: Vec::new(),
            delivered_messages: Vec::new(),
            next_log_index: HashMap::new(),
            key_packages,
            partitioned: HashMap::new(),
            disconnected: HashMap::new(),
            group_info: HashMap::new(),
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
            Operation::ExternalJoin { joiner_id, room_id } => {
                self.apply_external_join(*joiner_id, *room_id)
            },
            Operation::RemoveMember { remover_id, target_id, room_id } => {
                self.apply_remove_member(*remover_id, *target_id, *room_id)
            },
            Operation::AdvanceTime { .. } => OperationResult::Ok,
            Operation::DeliverPending => {
                self.apply_deliver_pending();
                OperationResult::Ok
            },
            Operation::Partition { client_id } => self.apply_partition(*client_id),
            Operation::HealPartition { client_id } => self.apply_heal_partition(*client_id),
            Operation::Disconnect { client_id } => self.apply_disconnect(*client_id),
        }
    }

    fn apply_deliver_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending_frames);

        for pf in pending {
            for &recipient_id in &pf.recipients {
                if self.partitioned.get(&recipient_id).copied().unwrap_or(false) {
                    continue;
                }
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
                if frame.header.opcode_enum() == Some(Opcode::Welcome) {
                    return Some(frame.clone());
                }
            }
            None
        });

        // Deliver commits immediately so members can process the epoch transition
        for action in &actions {
            if let ClientAction::Send(frame) = action {
                if frame.header.opcode_enum() == Some(Opcode::Commit) {
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

    fn apply_external_join(
        &mut self,
        joiner_id: ClientId,
        room_id: ModelRoomId,
    ) -> OperationResult {
        if joiner_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if self.room_membership.get(&(joiner_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::AlreadyMember);
        }

        let group_info_bytes = match self.group_info.get(&room_id) {
            Some(gi) => gi.clone(),
            None => return OperationResult::Error(OperationError::NoGroupInfo),
        };

        let real_room_id = room_id as u128 + 1;

        let joiner = &mut self.clients[joiner_id as usize];
        if joiner.handle(ClientEvent::ExternalJoin { room_id: real_room_id }).is_err() {
            return OperationResult::Error(OperationError::NoGroupInfo);
        }

        let current_epoch = self
            .room_epochs
            .iter()
            .find(|&(&(_, rid), _)| rid == room_id)
            .map(|(_, &e)| e)
            .unwrap_or(0);

        let payload =
            GroupInfoPayload { room_id: real_room_id, epoch: current_epoch, group_info_bytes };

        let frame =
            match Payload::GroupInfo(payload).into_frame(FrameHeader::new(Opcode::GroupInfo)) {
                Ok(f) => f,
                Err(_) => return OperationResult::Error(OperationError::NoGroupInfo),
            };

        let join_actions = match joiner.handle(ClientEvent::FrameReceived(frame)) {
            Ok(actions) => actions,
            Err(_) => return OperationResult::Error(OperationError::NoGroupInfo),
        };

        let commit = join_actions.iter().find_map(|a| {
            if let ClientAction::Send(frame) = a {
                if matches!(
                    frame.header.opcode_enum(),
                    Some(Opcode::Commit) | Some(Opcode::ExternalCommit)
                ) {
                    return Some(frame.clone());
                }
            }
            None
        });

        if let Some(commit) = commit {
            let existing_members: Vec<ClientId> = self
                .room_membership
                .iter()
                .filter(|&(&(_, rid), &m)| m && rid == room_id)
                .map(|(&(cid, _), _)| cid)
                .collect();

            for member_id in existing_members {
                if let Some(client) = self.clients.get_mut(member_id as usize) {
                    let _ = client.handle(ClientEvent::FrameReceived(commit.clone()));
                }
            }
        }

        for action in &join_actions {
            if let ClientAction::Send(frame) = action {
                if frame.header.opcode_enum() == Some(Opcode::GroupInfo) {
                    if let Ok(Payload::GroupInfo(gi)) = Payload::from_frame(frame.clone()) {
                        self.group_info.insert(room_id, gi.group_info_bytes);
                    }
                }
            }
        }

        let new_epoch = current_epoch + 1;
        let existing_members: Vec<ClientId> = self
            .room_membership
            .iter()
            .filter(|&(&(_, rid), &m)| m && rid == room_id)
            .map(|(&(cid, _), _)| cid)
            .collect();

        for cid in &existing_members {
            let epoch = self.room_epochs.entry((*cid, room_id)).or_insert(0);
            *epoch += 1;
        }

        self.room_membership.insert((joiner_id, room_id), true);
        self.room_epochs.insert((joiner_id, room_id), new_epoch);

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

        // Deliver commits immediately so members can process the epoch transition
        for action in &actions {
            if let ClientAction::Send(frame) = action {
                if frame.header.opcode_enum() == Some(Opcode::Commit) {
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
        if client_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if self.disconnected.get(&client_id).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::Disconnected);
        }

        let real_room_id = room_id as u128 + 1;

        if self.room_membership.get(&(client_id, room_id)).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::RoomAlreadyExists);
        }

        let client = &mut self.clients[client_id as usize];
        let result = client.handle(ClientEvent::CreateRoom { room_id: real_room_id });

        match result {
            Ok(actions) => {
                self.room_membership.insert((client_id, room_id), true);
                self.room_epochs.insert((client_id, room_id), 0);

                for action in &actions {
                    if let ClientAction::Send(frame) = action {
                        if frame.header.opcode_enum() == Some(Opcode::GroupInfo) {
                            if let Ok(Payload::GroupInfo(gi)) = Payload::from_frame(frame.clone()) {
                                self.group_info.insert(room_id, gi.group_info_bytes);
                            }
                        }
                    }
                }

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

        if self.partitioned.get(&client_id).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::Partitioned);
        }

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

                        // Store directly, we can't decrypt own message due to ratchet advance
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

                if remaining.is_empty() {
                    self.group_info.remove(&room_id);
                }

                for cid in &remaining {
                    let epoch = self.room_epochs.entry((*cid, room_id)).or_insert(0);
                    *epoch += 1;
                }

                OperationResult::Ok
            },
            Err(_) => OperationResult::Error(OperationError::NotMember),
        }
    }

    fn apply_partition(&mut self, client_id: ClientId) -> OperationResult {
        if client_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if self.disconnected.get(&client_id).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::Disconnected);
        }

        self.partitioned.insert(client_id, true);
        OperationResult::Ok
    }

    fn apply_heal_partition(&mut self, client_id: ClientId) -> OperationResult {
        if client_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if self.disconnected.get(&client_id).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::Disconnected);
        }

        self.partitioned.insert(client_id, false);
        OperationResult::Ok
    }

    fn apply_disconnect(&mut self, client_id: ClientId) -> OperationResult {
        if client_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if self.disconnected.get(&client_id).copied().unwrap_or(false) {
            return OperationResult::Error(OperationError::Disconnected);
        }

        self.disconnected.insert(client_id, true);
        self.partitioned.insert(client_id, true);

        let rooms: Vec<ModelRoomId> = self
            .room_membership
            .iter()
            .filter(|&(&(cid, _), &m)| m && cid == client_id)
            .map(|(&(_, rid), _)| rid)
            .collect();

        for room_id in rooms {
            self.room_membership.insert((client_id, room_id), false);
            self.room_epochs.remove(&(client_id, room_id));

            let remaining: Vec<ClientId> = self
                .room_membership
                .iter()
                .filter(|&(&(_, rid), &m)| m && rid == room_id)
                .map(|(&(cid, _), _)| cid)
                .collect();

            if remaining.is_empty() {
                self.group_info.remove(&room_id);
            }

            for cid in &remaining {
                let epoch = self.room_epochs.entry((*cid, room_id)).or_insert(0);
                *epoch += 1;
            }
        }

        OperationResult::Ok
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
        2 => (client_id.clone(), room_id.clone()).prop_map(|(j, r)| {
            Operation::ExternalJoin { joiner_id: j, room_id: r }
        }),
        1 => (client_id.clone(), client_id.clone(), room_id.clone()).prop_map(|(r, t, room)| {
            Operation::RemoveMember { remover_id: r, target_id: t, room_id: room }
        }),
        1 => millis.prop_map(|m| Operation::AdvanceTime { millis: m }),
        1 => Just(Operation::DeliverPending),
        1 => client_id.clone().prop_map(|c| Operation::Partition { client_id: c }),
        1 => client_id.clone().prop_map(|c| Operation::HealPartition { client_id: c }),
        1 => client_id.clone().prop_map(|c| Operation::Disconnect { client_id: c }),
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

        prop_assert_eq!(
            model_state.client_messages,
            real_state.client_messages,
            "Message divergence"
        );
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

    /// Verify partitioned clients cannot send messages.
    #[test]
    fn prop_partition_blocks_send(
        client_id in 0..4u8,
        room_id in any::<ModelRoomId>(),
        content in small_message_strategy()
    ) {
        let mut model = ModelWorld::new(4);

        let _ = model.apply(&Operation::CreateRoom { client_id, room_id });
        let _ = model.apply(&Operation::Partition { client_id });

        let result = model.apply(&Operation::SendMessage { client_id, room_id, content });
        prop_assert!(result.is_err(), "Partitioned client should not be able to send");

        if let OperationResult::Error(e) = result {
            prop_assert_eq!(e, OperationError::Partitioned);
        }
    }

    /// Verify healing partition restores send capability.
    #[test]
    fn prop_heal_partition_restores_send(
        client_id in 0..4u8,
        room_id in any::<ModelRoomId>(),
        content in small_message_strategy()
    ) {
        let mut model = ModelWorld::new(4);

        let _ = model.apply(&Operation::CreateRoom { client_id, room_id });
        let _ = model.apply(&Operation::Partition { client_id });
        let _ = model.apply(&Operation::HealPartition { client_id });

        let result = model.apply(&Operation::SendMessage { client_id, room_id, content });
        prop_assert!(result.is_ok(), "Healed client should be able to send");
    }

    /// Verify partitioned clients don't receive messages.
    #[test]
    fn prop_partition_blocks_receive(
        sender in 0..4u8,
        receiver in 0..4u8,
        room_id in any::<ModelRoomId>(),
        content in small_message_strategy()
    ) {
        prop_assume!(sender != receiver);

        let mut model = ModelWorld::new(4);

        let _ = model.apply(&Operation::CreateRoom { client_id: sender, room_id });
        let _ = model.apply(&Operation::AddMember { inviter_id: sender, invitee_id: receiver, room_id });
        let _ = model.apply(&Operation::Partition { client_id: receiver });
        let _ = model.apply(&Operation::SendMessage { client_id: sender, room_id, content });
        let _ = model.apply(&Operation::DeliverPending);

        let receiver_msgs = model.client_messages(receiver, room_id);
        prop_assert!(
            receiver_msgs.map(|m| m.is_empty()).unwrap_or(true),
            "Partitioned client should not receive messages"
        );
    }

    /// Verify disconnect removes client from all rooms.
    #[test]
    fn prop_disconnect_clears_membership(
        client_id in 0..4u8,
        room_ids in prop::collection::vec(any::<ModelRoomId>(), 1..4)
    ) {
        let mut model = ModelWorld::new(4);

        for &room_id in &room_ids {
            let _ = model.apply(&Operation::CreateRoom { client_id, room_id });
        }

        let _ = model.apply(&Operation::Disconnect { client_id });

        let rooms = model.client_rooms(client_id);
        prop_assert!(rooms.is_empty(), "Disconnected client should have no rooms");
    }

    /// Verify disconnected client cannot perform operations.
    #[test]
    fn prop_disconnect_blocks_operations(
        client_id in 0..4u8,
        room_id in any::<ModelRoomId>()
    ) {
        let mut model = ModelWorld::new(4);

        let _ = model.apply(&Operation::Disconnect { client_id });

        let result = model.apply(&Operation::CreateRoom { client_id, room_id });
        prop_assert!(result.is_err(), "Disconnected client should not create room");

        if let OperationResult::Error(e) = result {
            prop_assert_eq!(e, OperationError::Disconnected);
        }
    }

    /// Verify rejoin scenario: client leaves then gets re-added.
    #[test]
    fn prop_rejoin_after_leave(
        creator in 0..4u8,
        rejoiner in 0..4u8,
        room_id in any::<ModelRoomId>(),
        msg1 in small_message_strategy(),
        msg2 in small_message_strategy()
    ) {
        prop_assume!(creator != rejoiner);

        let mut model = ModelWorld::new(4);

        // Setup: creator makes room, adds rejoiner
        let _ = model.apply(&Operation::CreateRoom { client_id: creator, room_id });
        let _ = model.apply(&Operation::AddMember {
            inviter_id: creator,
            invitee_id: rejoiner,
            room_id,
        });

        // Rejoiner sends a message, then leaves
        let result = model.apply(&Operation::SendMessage {
            client_id: rejoiner,
            room_id,
            content: msg1,
        });
        prop_assert!(result.is_ok(), "Member should send before leaving");

        let _ = model.apply(&Operation::LeaveRoom { client_id: rejoiner, room_id });

        // Rejoiner can't send after leaving
        let result = model.apply(&Operation::SendMessage {
            client_id: rejoiner,
            room_id,
            content: msg2.clone(),
        });
        prop_assert!(result.is_err(), "Left member should not send");

        // Creator re-adds rejoiner
        let result = model.apply(&Operation::AddMember {
            inviter_id: creator,
            invitee_id: rejoiner,
            room_id,
        });
        prop_assert!(result.is_ok(), "Re-adding left member should succeed");

        // Rejoiner can send again
        let result = model.apply(&Operation::SendMessage {
            client_id: rejoiner,
            room_id,
            content: msg2,
        });
        prop_assert!(result.is_ok(), "Rejoined member should send");
    }

    /// Verify multi-party messaging with interleaved partitions.
    #[test]
    fn prop_multiparty_with_partitions(
        room_id in any::<ModelRoomId>(),
        messages in prop::collection::vec(small_message_strategy(), 3..8)
    ) {
        let mut model = ModelWorld::new(3);

        // Setup room with all 3 clients
        let _ = model.apply(&Operation::CreateRoom { client_id: 0, room_id });
        let _ = model.apply(&Operation::AddMember { inviter_id: 0, invitee_id: 1, room_id });
        let _ = model.apply(&Operation::AddMember { inviter_id: 0, invitee_id: 2, room_id });

        // Partition client 1
        let _ = model.apply(&Operation::Partition { client_id: 1 });

        // Client 0 and 2 exchange messages while 1 is partitioned
        for (i, content) in messages.iter().enumerate() {
            let sender = if i % 2 == 0 { 0 } else { 2 };
            let _ = model.apply(&Operation::SendMessage {
                client_id: sender,
                room_id,
                content: content.clone(),
            });
        }

        // Deliver to non-partitioned clients
        let _ = model.apply(&Operation::DeliverPending);

        // Client 1 should have no messages (was partitioned during send and delivery)
        let client1_msgs = model.client_messages(1, room_id);
        prop_assert!(
            client1_msgs.map(|m| m.is_empty()).unwrap_or(true),
            "Partitioned client should not receive messages"
        );

        // Clients 0 and 2 should have all messages
        let client0_msgs = model.client_messages(0, room_id);
        let client2_msgs = model.client_messages(2, room_id);
        prop_assert_eq!(
            client0_msgs.map(|m| m.len()).unwrap_or(0),
            messages.len(),
            "Active client 0 should have all messages"
        );
        prop_assert_eq!(
            client2_msgs.map(|m| m.len()).unwrap_or(0),
            messages.len(),
            "Active client 2 should have all messages"
        );

        // Heal partition - client 1 still won't have missed messages
        let _ = model.apply(&Operation::HealPartition { client_id: 1 });

        // Send one more message after heal
        let _ = model.apply(&Operation::SendMessage {
            client_id: 0,
            room_id,
            content: SmallMessage { seed: 99, size_class: 0 },
        });
        let _ = model.apply(&Operation::DeliverPending);

        // Now client 1 should have just the post-heal message
        let client1_msgs_after = model.client_messages(1, room_id);
        prop_assert_eq!(
            client1_msgs_after.map(|m| m.len()).unwrap_or(0),
            1,
            "Healed client should receive new messages"
        );
    }

    /// Verify concurrent membership changes maintain consistency.
    #[test]
    fn prop_concurrent_membership_changes(
        room_id in any::<ModelRoomId>(),
        ops_count in 5..15usize
    ) {
        let mut model = ModelWorld::new(4);

        // Client 0 creates room
        let _ = model.apply(&Operation::CreateRoom { client_id: 0, room_id });

        let mut expected_members: std::collections::HashSet<ClientId> =
            std::iter::once(0).collect();

        for i in 0..ops_count {
            let target = ((i % 3) + 1) as u8; // Clients 1, 2, 3

            if expected_members.contains(&target) {
                // Target is member, try to remove
                let result = model.apply(&Operation::RemoveMember {
                    remover_id: 0,
                    target_id: target,
                    room_id,
                });
                prop_assert!(result.is_ok(), "Remove existing member should succeed");
                expected_members.remove(&target);
            } else {
                // Target is not member, try to add
                let result = model.apply(&Operation::AddMember {
                    inviter_id: 0,
                    invitee_id: target,
                    room_id,
                });
                prop_assert!(result.is_ok(), "Add non-member should succeed");
                expected_members.insert(target);
            }

            // Verify membership matches expectation
            let actual_rooms = model.client_rooms(target);
            let is_member = actual_rooms.contains(&room_id);
            prop_assert_eq!(
                is_member,
                expected_members.contains(&target),
                "Membership mismatch for client {} after op {}", target, i
            );
        }

        // Verify epoch increased with each membership change
        let state = model.observable_state();
        let creator_epochs = &state.client_epochs[0];
        if let Some((_, epoch)) = creator_epochs.iter().find(|(r, _)| *r == room_id) {
            prop_assert!(
                *epoch >= ops_count as u64,
                "Epoch should advance with each membership change"
            );
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
