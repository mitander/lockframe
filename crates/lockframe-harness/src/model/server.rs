//! Model server state machine.
//!
//! Simplified server that tracks rooms and assigns log indices.
//! The server is the source of truth for message ordering.

use std::collections::{HashMap, HashSet};

use super::{
    client::ModelMessage,
    operation::{ClientId, ModelRoomId, OperationError},
};

/// Per-room state on the server.
#[derive(Debug, Clone)]
struct ServerRoomState {
    /// Room creator (for authorization in future).
    #[allow(dead_code)]
    creator: ClientId,
    /// Members of the room.
    members: HashSet<ClientId>,
    /// All messages in order.
    messages: Vec<ModelMessage>,
    /// Next log index to assign.
    next_log_index: u64,
    /// Current epoch.
    epoch: u64,
}

impl ServerRoomState {
    fn new(creator: ClientId) -> Self {
        let mut members = HashSet::new();
        members.insert(creator);

        Self { creator, members, messages: Vec::new(), next_log_index: 0, epoch: 0 }
    }
}

/// Maximum pending deliveries before invariant violation.
const MAX_PENDING_DELIVERIES: usize = 1000;

/// Message waiting for delivery.
#[derive(Debug, Clone)]
pub struct PendingMessage {
    /// Target room.
    pub room_id: ModelRoomId,
    /// Message to deliver.
    pub message: ModelMessage,
    /// Recipients (snapshot at send time).
    pub recipients: Vec<ClientId>,
}

/// Model server state.
///
/// Tracks all rooms and their message logs.
#[derive(Debug, Clone)]
pub struct ModelServer {
    /// Active rooms.
    rooms: HashMap<ModelRoomId, ServerRoomState>,
    /// Messages waiting for delivery.
    pending_deliveries: Vec<PendingMessage>,
}

impl ModelServer {
    /// Create a new model server.
    pub fn new() -> Self {
        Self { rooms: HashMap::new(), pending_deliveries: Vec::new() }
    }

    /// Number of messages waiting for delivery.
    pub fn pending_count(&self) -> usize {
        self.pending_deliveries.len()
    }

    /// Take all pending messages for delivery.
    pub fn take_pending(&mut self) -> Vec<PendingMessage> {
        std::mem::take(&mut self.pending_deliveries)
    }

    /// Check if a room exists.
    pub fn room_exists(&self, room_id: ModelRoomId) -> bool {
        self.rooms.contains_key(&room_id)
    }

    /// Check if a client is a member of a room.
    pub fn is_member(&self, room_id: ModelRoomId, client_id: ClientId) -> bool {
        self.rooms.get(&room_id).is_some_and(|r| r.members.contains(&client_id))
    }

    /// Members of a room.
    pub fn members(&self, room_id: ModelRoomId) -> Option<impl Iterator<Item = ClientId> + '_> {
        self.rooms.get(&room_id).map(|r| r.members.iter().copied())
    }

    /// Messages in a room (ordered by `log_index`).
    pub fn messages(&self, room_id: ModelRoomId) -> Option<&[ModelMessage]> {
        self.rooms.get(&room_id).map(|r| r.messages.as_slice())
    }

    /// Current epoch for a room.
    pub fn epoch(&self, room_id: ModelRoomId) -> Option<u64> {
        self.rooms.get(&room_id).map(|r| r.epoch)
    }

    /// Create a new room.
    pub fn create_room(
        &mut self,
        room_id: ModelRoomId,
        creator: ClientId,
    ) -> Result<(), OperationError> {
        if self.rooms.contains_key(&room_id) {
            return Err(OperationError::RoomAlreadyExists);
        }

        self.rooms.insert(room_id, ServerRoomState::new(creator));
        Ok(())
    }

    /// Process a message from a client.
    ///
    /// Assigns `log_index` and stores the message. The message is queued for
    /// pending delivery (call `take_pending` to get messages for delivery).
    pub fn process_message(
        &mut self,
        room_id: ModelRoomId,
        sender_id: ClientId,
        content: Vec<u8>,
    ) -> Result<ModelMessage, OperationError> {
        let room = self.rooms.get_mut(&room_id).ok_or(OperationError::RoomNotFound)?;

        if !room.members.contains(&sender_id) {
            return Err(OperationError::NotMember);
        }

        let log_index = room.next_log_index;
        room.next_log_index += 1;

        let epoch = room.epoch;
        let message = ModelMessage { sender_id, content, log_index, epoch };

        room.messages.push(message.clone());

        let recipients: Vec<ClientId> = room.members.iter().copied().collect();

        debug_assert!(
            self.pending_deliveries.len() < MAX_PENDING_DELIVERIES,
            "invariant: pending delivery queue exceeded bound"
        );
        self.pending_deliveries.push(PendingMessage {
            room_id,
            message: message.clone(),
            recipients,
        });

        Ok(message)
    }

    /// Remove a member from a room.
    ///
    /// Rooms persist even when all members leave.
    pub fn remove_member(
        &mut self,
        room_id: ModelRoomId,
        client_id: ClientId,
    ) -> Result<(), OperationError> {
        let room = self.rooms.get_mut(&room_id).ok_or(OperationError::RoomNotFound)?;

        if !room.members.remove(&client_id) {
            return Err(OperationError::NotMember);
        }

        Ok(())
    }

    /// Add a member to a room.
    pub fn add_member(&mut self, room_id: ModelRoomId, client_id: ClientId) {
        if let Some(room) = self.rooms.get_mut(&room_id) {
            room.members.insert(client_id);
        }
    }

    /// Advance epoch for a room.
    pub fn advance_epoch(&mut self, room_id: ModelRoomId) {
        if let Some(room) = self.rooms.get_mut(&room_id) {
            room.epoch += 1;
        }
    }
}

impl Default for ModelServer {
    fn default() -> Self {
        Self::new()
    }
}
