//! Model world - orchestrates clients and server.
//!
//! The world is the top-level container that manages the model state
//! and applies operations. It's the oracle against which the real
//! implementation is verified.

use super::{
    client::{ModelClient, ModelMessage},
    operation::{ClientId, ModelRoomId, Operation, OperationError, OperationResult},
    server::ModelServer,
};

/// Observable state for oracle comparison.
///
/// This is the subset of world state that can be compared
/// against the real implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservableState {
    /// Per-client room memberships (sorted).
    pub client_rooms: Vec<Vec<ModelRoomId>>,
    /// Per-client, per-room message lists.
    pub client_messages: Vec<Vec<(ModelRoomId, Vec<ModelMessage>)>>,
    /// Per-client, per-room epochs.
    pub client_epochs: Vec<Vec<(ModelRoomId, u64)>>,
    /// Server's view of messages per room.
    pub server_messages: Vec<(ModelRoomId, Vec<ModelMessage>)>,
}

/// Model world - the reference implementation.
///
/// Manages multiple clients and a single server, applying operations
/// and tracking state for oracle comparison.
#[derive(Debug, Clone)]
pub struct ModelWorld {
    /// Model clients (indexed by `ClientId`).
    clients: Vec<ModelClient>,
    /// Model server.
    server: ModelServer,
}

impl ModelWorld {
    /// Create a new model world with the given number of clients.
    pub fn new(num_clients: usize) -> Self {
        let clients = (0..num_clients).map(|i| ModelClient::new(i as ClientId)).collect();

        Self { clients, server: ModelServer::new() }
    }

    /// Number of clients in the world.
    pub fn num_clients(&self) -> usize {
        self.clients.len()
    }

    /// Get a client by ID.
    pub fn client(&self, id: ClientId) -> Option<&ModelClient> {
        self.clients.get(id as usize)
    }

    /// Get the server.
    pub fn server(&self) -> &ModelServer {
        &self.server
    }

    /// Apply an operation and return the result.
    ///
    /// This is the main entry point for model-based testing.
    /// The result should match the real implementation's result.
    pub fn apply(&mut self, op: &Operation) -> OperationResult {
        match op {
            Operation::CreateRoom { client_id, room_id } => {
                self.apply_create_room(*client_id, *room_id)
            },
            Operation::SendMessage { client_id, room_id, content } => {
                self.apply_send_message(*client_id, *room_id, content.to_bytes())
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
            Operation::AdvanceTime { .. } => {
                // Model doesn't track time
                OperationResult::Ok
            },
            Operation::DeliverPending => {
                self.apply_deliver_pending();
                OperationResult::Ok
            },
            Operation::Partition { client_id } => self.apply_partition(*client_id),
            Operation::HealPartition { client_id } => self.apply_heal_partition(*client_id),
            Operation::Disconnect { client_id } => self.apply_disconnect(*client_id),
        }
    }

    /// Extract observable state for comparison.
    pub fn observable_state(&self) -> ObservableState {
        let mut client_rooms = Vec::with_capacity(self.clients.len());
        let mut client_messages = Vec::with_capacity(self.clients.len());
        let mut client_epochs = Vec::with_capacity(self.clients.len());

        for client in &self.clients {
            let mut rooms: Vec<_> = client.rooms().collect();
            rooms.sort_unstable();
            client_rooms.push(rooms.clone());

            let mut messages = Vec::new();
            let mut epochs = Vec::new();
            for room_id in rooms {
                if let Some(msgs) = client.messages(room_id) {
                    messages.push((room_id, msgs.to_vec()));
                }
                if let Some(epoch) = client.epoch(room_id) {
                    epochs.push((room_id, epoch));
                }
            }
            client_messages.push(messages);
            client_epochs.push(epochs);
        }

        let mut server_messages = Vec::new();
        let mut room_ids: Vec<_> = self
            .clients
            .iter()
            .flat_map(super::client::ModelClient::rooms)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        room_ids.sort_unstable();

        for room_id in room_ids {
            if let Some(msgs) = self.server.messages(room_id) {
                server_messages.push((room_id, msgs.to_vec()));
            }
        }

        ObservableState { client_rooms, client_messages, client_epochs, server_messages }
    }

    /// Apply create room operation.
    ///
    /// Note: Each client can independently create a room with the same ID.
    /// There is no centralized room registry - room creation is local.
    fn apply_create_room(&mut self, client_id: ClientId, room_id: ModelRoomId) -> OperationResult {
        let Some(client) = self.clients.get_mut(client_id as usize) else {
            return OperationResult::Error(OperationError::InvalidClient);
        };

        if client.is_disconnected() {
            return OperationResult::Error(OperationError::Disconnected);
        }

        if self.server.room_exists(room_id) {
            return OperationResult::Error(OperationError::RoomAlreadyExists);
        }

        let client_result = client.create_room(room_id);
        if client_result.is_err() {
            return client_result;
        }

        self.server.create_room(room_id, client_id).expect("room existence already checked");
        self.server.add_member(room_id, client_id);

        OperationResult::Ok
    }

    /// Apply send message operation.
    ///
    /// Sender receives their own message immediately (can't decrypt after
    /// ratchet advance). Other recipients receive via
    /// `apply_deliver_pending`.
    fn apply_send_message(
        &mut self,
        client_id: ClientId,
        room_id: ModelRoomId,
        content: Vec<u8>,
    ) -> OperationResult {
        if client_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        let client = &self.clients[client_id as usize];
        if client.is_partitioned() {
            return OperationResult::Error(OperationError::Partitioned);
        }

        if !client.is_member(room_id) {
            return OperationResult::Error(OperationError::NotMember);
        }

        match self.server.process_message(room_id, client_id, content) {
            Ok(message) => {
                self.clients[client_id as usize].receive_message(room_id, message);
                OperationResult::Ok
            },
            Err(e) => OperationResult::Error(e),
        }
    }

    /// Deliver all pending messages to their recipients.
    fn apply_deliver_pending(&mut self) {
        let pending = self.server.take_pending();

        for pending_msg in pending {
            let sender_id = pending_msg.message.sender_id;
            for recipient_id in pending_msg.recipients {
                if recipient_id == sender_id {
                    continue;
                }
                if let Some(client) = self.clients.get_mut(recipient_id as usize) {
                    if client.is_partitioned() {
                        continue;
                    }
                    if client.is_member(pending_msg.room_id) {
                        client.receive_message(pending_msg.room_id, pending_msg.message.clone());
                    }
                }
            }
        }
    }

    /// Apply leave room operation.
    ///
    /// Self-initiated departure. Advances epoch.
    fn apply_leave_room(&mut self, client_id: ClientId, room_id: ModelRoomId) -> OperationResult {
        let Some(client) = self.clients.get_mut(client_id as usize) else {
            return OperationResult::Error(OperationError::InvalidClient);
        };

        let result = client.leave_room(room_id);
        if result.is_err() {
            return result;
        }

        let _ = self.server.remove_member(room_id, client_id);
        self.server.advance_epoch(room_id);

        for other_client in &mut self.clients {
            if other_client.is_member(room_id) {
                other_client.advance_epoch(room_id);
            }
        }

        OperationResult::Ok
    }

    /// Apply add member operation.
    ///
    /// Inviter adds invitee to the room. Advances epoch.
    fn apply_add_member(
        &mut self,
        sender_id: ClientId,
        recipient_id: ClientId,
        room_id: ModelRoomId,
    ) -> OperationResult {
        if sender_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }
        if recipient_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if !self.clients[sender_id as usize].is_member(room_id) {
            return OperationResult::Error(OperationError::NotMember);
        }

        if self.clients[recipient_id as usize].is_member(room_id) {
            return OperationResult::Error(OperationError::AlreadyMember);
        }

        self.server.advance_epoch(room_id);
        let new_epoch = self.server.epoch(room_id).unwrap_or(0);

        for client in &mut self.clients {
            if client.is_member(room_id) {
                client.advance_epoch(room_id);
            }
        }

        self.server.add_member(room_id, recipient_id);
        let _ = self.clients[recipient_id as usize].join_room_at_epoch(room_id, new_epoch);

        OperationResult::Ok
    }

    /// Apply external join operation.
    ///
    /// Joiner joins using `GroupInfo` (no inviter needed). Advances epoch.
    fn apply_external_join(
        &mut self,
        joiner_id: ClientId,
        room_id: ModelRoomId,
    ) -> OperationResult {
        if joiner_id as usize >= self.clients.len() {
            return OperationResult::Error(OperationError::InvalidClient);
        }

        if self.clients[joiner_id as usize].is_member(room_id) {
            return OperationResult::Error(OperationError::AlreadyMember);
        }

        if self.server.epoch(room_id).is_none() {
            return OperationResult::Error(OperationError::NoGroupInfo);
        }

        self.server.advance_epoch(room_id);
        let new_epoch = self.server.epoch(room_id).unwrap_or(0);

        for client in &mut self.clients {
            if client.is_member(room_id) {
                client.advance_epoch(room_id);
            }
        }

        self.server.add_member(room_id, joiner_id);
        let _ = self.clients[joiner_id as usize].join_room_at_epoch(room_id, new_epoch);

        OperationResult::Ok
    }

    /// Apply remove member operation.
    ///
    /// Remover kicks target from the room. Cannot remove self.
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

        if !self.clients[remover_id as usize].is_member(room_id) {
            return OperationResult::Error(OperationError::NotMember);
        }

        if !self.clients[target_id as usize].is_member(room_id) {
            return OperationResult::Error(OperationError::NotMember);
        }

        let _ = self.clients[target_id as usize].leave_room(room_id);

        let _ = self.server.remove_member(room_id, target_id);
        self.server.advance_epoch(room_id);

        for client in &mut self.clients {
            if client.is_member(room_id) {
                client.advance_epoch(room_id);
            }
        }

        OperationResult::Ok
    }

    /// Messages visible to a client in a room.
    pub fn client_messages(
        &self,
        client_id: ClientId,
        room_id: ModelRoomId,
    ) -> Option<&[ModelMessage]> {
        self.clients.get(client_id as usize).and_then(|c| c.messages(room_id))
    }

    /// All rooms a client is a member of.
    pub fn client_rooms(&self, client_id: ClientId) -> Vec<ModelRoomId> {
        self.clients.get(client_id as usize).map(|c| c.rooms().collect()).unwrap_or_default()
    }

    /// Partition a client from the server.
    fn apply_partition(&mut self, client_id: ClientId) -> OperationResult {
        let Some(client) = self.clients.get_mut(client_id as usize) else {
            return OperationResult::Error(OperationError::InvalidClient);
        };

        if client.is_disconnected() {
            return OperationResult::Error(OperationError::Disconnected);
        }

        client.partition();
        OperationResult::Ok
    }

    /// Heal a partition, restoring connectivity.
    fn apply_heal_partition(&mut self, client_id: ClientId) -> OperationResult {
        let Some(client) = self.clients.get_mut(client_id as usize) else {
            return OperationResult::Error(OperationError::InvalidClient);
        };

        if client.is_disconnected() {
            return OperationResult::Error(OperationError::Disconnected);
        }

        client.heal_partition();
        OperationResult::Ok
    }

    /// Disconnect a client, removing from all rooms.
    fn apply_disconnect(&mut self, client_id: ClientId) -> OperationResult {
        let Some(client) = self.clients.get_mut(client_id as usize) else {
            return OperationResult::Error(OperationError::InvalidClient);
        };

        if client.is_disconnected() {
            return OperationResult::Error(OperationError::Disconnected);
        }

        let rooms = client.disconnect();

        for room_id in rooms {
            let _ = self.server.remove_member(room_id, client_id);

            // Only advance epoch if there are remaining members (they process the removal)
            let has_remaining_members =
                self.server.members(room_id).is_some_and(|mut m| m.any(|_| true));

            if has_remaining_members {
                self.server.advance_epoch(room_id);
                for other_client in &mut self.clients {
                    if other_client.is_member(room_id) {
                        other_client.advance_epoch(room_id);
                    }
                }
            }
        }

        OperationResult::Ok
    }
}
