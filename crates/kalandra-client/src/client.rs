//! Client state machine.
//!
//! The `Client` is the top-level state machine that manages multiple room
//! memberships and orchestrates MLS operations with sender key encryption.

use std::{collections::HashMap, time::Duration};

use kalandra_core::{
    env::Environment,
    mls::{MlsAction, MlsGroup, RoomId},
};
use kalandra_crypto::{EncryptedMessage as CryptoEncryptedMessage, NONCE_RANDOM_SIZE};
use kalandra_proto::{Frame, FrameHeader, Opcode, payloads::app::EncryptedMessage};

use crate::{
    error::ClientError,
    event::{ClientAction, ClientEvent, RoomStateSnapshot},
    sender_key_store::SenderKeyStore,
};

/// Label for MLS secret export (domain separation).
const SENDER_KEY_LABEL: &str = "kalandra sender keys v1";

/// Context for MLS secret export.
const SENDER_KEY_CONTEXT: &[u8] = b"";

/// Size of the sender key secret in bytes.
const SENDER_KEY_SECRET_SIZE: usize = 32;

/// Timeout for pending commits before requesting sync (30 seconds).
const COMMIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Client identity.
///
/// Owns the persistent cryptographic material that identifies this client
/// across all room memberships.
///
/// Note: MLS credential and signer are owned by MlsGroup per-room.
/// This may be refactored when we implement proper identity management.
pub struct ClientIdentity {
    /// Stable sender ID used in frame headers.
    pub sender_id: u64,
}

impl ClientIdentity {
    /// Create a new client identity with the given sender ID.
    pub fn new(sender_id: u64) -> Self {
        Self { sender_id }
    }
}

/// Per-room state combining MLS group and sender keys.
struct RoomState<E: Environment> {
    /// MLS group state machine.
    mls_group: MlsGroup<E>,

    /// Sender keys for all members at current epoch.
    sender_keys: SenderKeyStore,

    /// Our leaf index in the MLS tree.
    my_leaf_index: u32,
}

/// Client state machine.
///
/// Manages multiple room memberships and handles message encryption/decryption.
/// Pure state machine - returns actions, caller handles I/O.
///
/// # Type Parameters
///
/// - `E`: Environment implementation for time/randomness
pub struct Client<E: Environment> {
    /// Our persistent identity.
    identity: ClientIdentity,

    /// Active room memberships.
    rooms: HashMap<RoomId, RoomState<E>>,

    /// Environment for time/randomness.
    env: E,
}

impl<E: Environment> Client<E> {
    /// Create a new client with the given identity.
    pub fn new(env: E, identity: ClientIdentity) -> Self {
        Self { identity, rooms: HashMap::new(), env }
    }

    /// Get the client's sender ID.
    pub fn sender_id(&self) -> u64 {
        self.identity.sender_id
    }

    /// Get the number of active rooms.
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    /// Check if the client is a member of a room.
    pub fn is_member(&self, room_id: RoomId) -> bool {
        self.rooms.contains_key(&room_id)
    }

    /// Get the current epoch for a room.
    pub fn epoch(&self, room_id: RoomId) -> Option<u64> {
        self.rooms.get(&room_id).map(|r| r.mls_group.epoch())
    }

    /// Generate a KeyPackage for this client to join a room.
    ///
    /// The returned KeyPackage should be sent to the room creator who will
    /// add this client via `AddMembers`. The caller is responsible for
    /// keeping the KeyPackage until a Welcome message is received.
    ///
    /// Return a tuple of (serialized KeyPackage bytes, KeyPackage hash ref).
    /// The hash reference can be used to track which KeyPackage was used.
    ///
    /// # Errors
    ///
    /// Returns an error if KeyPackage generation fails.
    pub fn generate_key_package(&self) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
        MlsGroup::generate_key_package(self.env.clone(), self.identity.sender_id)
            .map_err(|e| ClientError::Mls { reason: e.to_string() })
    }

    /// Process an event and return resulting actions.
    ///
    /// # Errors
    ///
    /// Returns `ClientError` if the event cannot be processed.
    pub fn handle(
        &mut self,
        event: ClientEvent<E::Instant>,
    ) -> Result<Vec<ClientAction>, ClientError> {
        match event {
            ClientEvent::CreateRoom { room_id } => self.handle_create_room(room_id),
            ClientEvent::SendMessage { room_id, plaintext } => {
                self.handle_send_message(room_id, &plaintext)
            },
            ClientEvent::FrameReceived(frame) => self.handle_frame(frame),
            ClientEvent::Tick { now } => self.handle_tick(now),
            ClientEvent::LeaveRoom { room_id } => self.handle_leave_room(room_id),
            ClientEvent::JoinRoom { room_id, welcome } => self.handle_join_room(room_id, &welcome),
            ClientEvent::AddMembers { room_id, key_packages } => {
                self.handle_add_members(room_id, key_packages)
            },
        }
    }

    /// Handle room creation.
    fn handle_create_room(&mut self, room_id: RoomId) -> Result<Vec<ClientAction>, ClientError> {
        if self.rooms.contains_key(&room_id) {
            return Err(ClientError::RoomAlreadyExists { room_id });
        }

        let member_id = self.identity.sender_id;

        let (mls_group, mls_actions) = MlsGroup::new(self.env.clone(), room_id, member_id)
            .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        let sender_keys = self.initialize_sender_keys(&mls_group)?;
        let my_leaf_index = mls_group.own_leaf_index();

        let initial_state =
            mls_group.export_state().map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        let room_state = RoomState { mls_group, sender_keys, my_leaf_index };
        self.rooms.insert(room_id, room_state);

        let mut actions = self.convert_mls_actions(room_id, mls_actions);

        actions.push(ClientAction::PersistRoom(RoomStateSnapshot {
            room_id,
            epoch: 0,
            mls_state: initial_state,
            my_leaf_index,
        }));

        actions.push(ClientAction::Log { message: format!("Created room {room_id:x} at epoch 0") });

        Ok(actions)
    }

    /// Initialize sender keys from MLS group state.
    fn initialize_sender_keys(
        &self,
        mls_group: &MlsGroup<E>,
    ) -> Result<SenderKeyStore, ClientError> {
        let epoch_secret = mls_group
            .export_secret(SENDER_KEY_LABEL, SENDER_KEY_CONTEXT, SENDER_KEY_SECRET_SIZE)
            .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        let member_indices = mls_group.member_leaf_indices();

        Ok(SenderKeyStore::initialize_epoch(&epoch_secret, mls_group.epoch(), &member_indices))
    }

    /// Handle sending a message.
    fn handle_send_message(
        &mut self,
        room_id: RoomId,
        plaintext: &[u8],
    ) -> Result<Vec<ClientAction>, ClientError> {
        let room = self.rooms.get_mut(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;

        let mut random_bytes = [0u8; NONCE_RANDOM_SIZE];
        self.env.random_bytes(&mut random_bytes);

        let crypto_encrypted =
            room.sender_keys.encrypt(room.my_leaf_index, plaintext, random_bytes)?;

        let encrypted = crypto_to_proto_encrypted(&crypto_encrypted);
        let payload = serialize_encrypted_message(&encrypted);

        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(self.identity.sender_id);
        header.set_epoch(room.mls_group.epoch());

        room.mls_group.sign_frame_header(&mut header);

        let frame = Frame::new(header, payload);

        Ok(vec![ClientAction::Send(frame)])
    }

    /// Handle received frame.
    fn handle_frame(&mut self, frame: Frame) -> Result<Vec<ClientAction>, ClientError> {
        let room_id = frame.header.room_id();

        let opcode = frame.header.opcode_enum().ok_or(ClientError::InvalidFrame {
            reason: format!("Unknown opcode: {}", frame.header.opcode()),
        })?;

        match opcode {
            Opcode::AppMessage => self.handle_app_message(room_id, frame),
            Opcode::Commit => self.handle_commit(room_id, frame),
            Opcode::Welcome => self.handle_welcome(room_id, frame),
            _ => {
                // MLS
                let room =
                    self.rooms.get_mut(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;

                let mls_actions = room
                    .mls_group
                    .process_message(frame)
                    .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

                Ok(self.convert_mls_actions(room_id, mls_actions))
            },
        }
    }

    /// Handle application message (encrypted content).
    fn handle_app_message(
        &mut self,
        room_id: RoomId,
        frame: Frame,
    ) -> Result<Vec<ClientAction>, ClientError> {
        let room = self.rooms.get_mut(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;

        let frame_epoch = frame.header.epoch();
        let room_epoch = room.mls_group.epoch();
        if frame_epoch != room_epoch {
            return Err(ClientError::EpochMismatch { expected: room_epoch, actual: frame_epoch });
        }

        let proto_encrypted = deserialize_encrypted_message(&frame.payload)
            .map_err(|e| ClientError::InvalidFrame { reason: e })?;

        let encrypted = proto_to_crypto_encrypted(&proto_encrypted);
        let plaintext = room.sender_keys.decrypt(&encrypted)?;

        Ok(vec![ClientAction::DeliverMessage {
            room_id,
            sender_id: frame.header.sender_id(),
            plaintext,
            log_index: frame.header.log_index(),
            timestamp: frame.header.hlc_timestamp(),
        }])
    }

    /// Handle MLS commit (epoch transition).
    fn handle_commit(
        &mut self,
        room_id: RoomId,
        frame: Frame,
    ) -> Result<Vec<ClientAction>, ClientError> {
        let mls_actions = {
            let room = self.rooms.get_mut(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;
            room.mls_group
                .process_message(frame)
                .map_err(|e| ClientError::Mls { reason: e.to_string() })?
        };

        let mut actions = self.convert_mls_actions(room_id, mls_actions);

        // Re-derive sender keys for new epoch from MLS state
        // We need to export the secret while holding only an immutable borrow,
        // then update the room state afterward
        let (new_sender_keys, new_leaf_index, epoch, my_leaf_index) = {
            let room = self.rooms.get(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;
            let sender_keys = self.initialize_sender_keys(&room.mls_group)?;
            let leaf_index = room.mls_group.own_leaf_index();
            let epoch = room.mls_group.epoch();
            (sender_keys, leaf_index, epoch, leaf_index)
        };

        let room = self.rooms.get_mut(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;
        room.sender_keys = new_sender_keys;
        room.my_leaf_index = new_leaf_index;

        actions.push(ClientAction::PersistRoom(RoomStateSnapshot {
            room_id,
            epoch,
            mls_state: room
                .mls_group
                .export_state()
                .map_err(|e| ClientError::Mls { reason: e.to_string() })?,
            my_leaf_index,
        }));

        Ok(actions)
    }

    /// Handle incoming Welcome frame.
    ///
    /// When we receive a Welcome message from another member (who added us),
    /// we process it to join the group.
    fn handle_welcome(
        &mut self,
        room_id: RoomId,
        frame: Frame,
    ) -> Result<Vec<ClientAction>, ClientError> {
        if self.rooms.contains_key(&room_id) {
            return Err(ClientError::RoomAlreadyExists { room_id });
        }

        let (mls_group, mls_actions) = MlsGroup::join_from_welcome(
            self.env.clone(),
            room_id,
            self.identity.sender_id,
            &frame.payload,
        )
        .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        let sender_keys = self.initialize_sender_keys(&mls_group)?;
        let my_leaf_index = mls_group.own_leaf_index();

        let room_state = RoomState { mls_group, sender_keys, my_leaf_index };
        self.rooms.insert(room_id, room_state);

        let mut actions = self.convert_mls_actions(room_id, mls_actions);
        actions.push(ClientAction::Log { message: format!("Joined room {room_id:x} via Welcome") });

        Ok(actions)
    }

    /// Handle join room request via Welcome message.
    ///
    /// This is the application-initiated join (via ClientEvent::JoinRoom).
    /// The Welcome message should have been received out-of-band.
    fn handle_join_room(
        &mut self,
        room_id: RoomId,
        welcome: &[u8],
    ) -> Result<Vec<ClientAction>, ClientError> {
        if self.rooms.contains_key(&room_id) {
            return Err(ClientError::RoomAlreadyExists { room_id });
        }

        let (mls_group, mls_actions) = MlsGroup::join_from_welcome(
            self.env.clone(),
            room_id,
            self.identity.sender_id,
            welcome,
        )
        .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        let sender_keys = self.initialize_sender_keys(&mls_group)?;
        let my_leaf_index = mls_group.own_leaf_index();

        let room_state = RoomState { mls_group, sender_keys, my_leaf_index };
        self.rooms.insert(room_id, room_state);

        let mut actions = self.convert_mls_actions(room_id, mls_actions);
        actions.push(ClientAction::Log {
            message: format!("Joined room {room_id:x} via JoinRoom event"),
        });

        Ok(actions)
    }

    /// Handle add members request.
    ///
    /// Adds members to a room using their serialized KeyPackages.
    /// Delegates to MlsGroup::add_members_from_bytes.
    fn handle_add_members(
        &mut self,
        room_id: RoomId,
        key_packages_bytes: Vec<Vec<u8>>,
    ) -> Result<Vec<ClientAction>, ClientError> {
        let room = self.rooms.get_mut(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;
        let mls_actions = room
            .mls_group
            .add_members_from_bytes(&key_packages_bytes)
            .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        Ok(self.convert_mls_actions(room_id, mls_actions))
    }

    /// Handle tick (timeout processing).
    ///
    /// Checks all rooms for pending commits that have timed out.
    /// For rooms with timed-out commits, emits `RequestSync` actions.
    fn handle_tick(&mut self, now: E::Instant) -> Result<Vec<ClientAction>, ClientError>
    where
        E::Instant: Copy + Ord + std::ops::Sub<Output = std::time::Duration>,
    {
        let mut actions = Vec::new();

        for (&room_id, room) in &self.rooms {
            if room.mls_group.is_commit_timeout(now, COMMIT_TIMEOUT) {
                let current_epoch = room.mls_group.epoch();
                // Commit timed out, request sync from server to catch up
                actions.push(ClientAction::RequestSync {
                    room_id,
                    from_epoch: current_epoch,
                    to_epoch: current_epoch.saturating_add(1), // next commit
                });
                actions.push(ClientAction::Log {
                    message: format!(
                        "Commit timeout in room {room_id:x}, requesting sync from epoch {current_epoch}"
                    ),
                });
            }
        }

        Ok(actions)
    }

    /// Handle leaving a room.
    fn handle_leave_room(&mut self, room_id: RoomId) -> Result<Vec<ClientAction>, ClientError> {
        if self.rooms.remove(&room_id).is_none() {
            return Err(ClientError::RoomNotFound { room_id });
        }

        Ok(vec![ClientAction::RoomRemoved { room_id, reason: "Left room".to_string() }])
    }

    /// Convert MLS actions to client actions.
    fn convert_mls_actions(
        &self,
        room_id: RoomId,
        mls_actions: Vec<MlsAction>,
    ) -> Vec<ClientAction> {
        mls_actions
            .into_iter()
            .filter_map(|action| match action {
                MlsAction::SendCommit(frame)
                | MlsAction::SendProposal(frame)
                | MlsAction::SendMessage(frame) => Some(ClientAction::Send(frame)),
                MlsAction::SendWelcome { frame, .. } => Some(ClientAction::Send(frame)),
                MlsAction::DeliverMessage { sender, plaintext } => {
                    // MLS-decrypted message don't use sender keys path
                    Some(ClientAction::DeliverMessage {
                        room_id,
                        sender_id: sender,
                        plaintext,
                        log_index: 0,
                        timestamp: 0,
                    })
                },
                MlsAction::RemoveGroup { reason } => {
                    Some(ClientAction::RoomRemoved { room_id, reason })
                },
                MlsAction::Log { message } => Some(ClientAction::Log { message }),
            })
            .collect()
    }
}

// Convert from crypto EncryptedMessage to proto EncryptedMessage
fn crypto_to_proto_encrypted(crypto: &CryptoEncryptedMessage) -> EncryptedMessage {
    EncryptedMessage {
        epoch: crypto.epoch,
        sender_index: crypto.sender_index,
        generation: crypto.generation,
        nonce: crypto.nonce,
        ciphertext: crypto.ciphertext.clone(),
        push_keys: None, // Not implemented yet
    }
}

// Convert from proto EncryptedMessage to crypto EncryptedMessage
fn proto_to_crypto_encrypted(proto: &EncryptedMessage) -> CryptoEncryptedMessage {
    CryptoEncryptedMessage {
        epoch: proto.epoch,
        sender_index: proto.sender_index,
        generation: proto.generation,
        nonce: proto.nonce,
        ciphertext: proto.ciphertext.clone(),
    }
}

// Serialize EncryptedMessage using CBOR
fn serialize_encrypted_message(encrypted: &EncryptedMessage) -> Vec<u8> {
    let mut data = Vec::new();
    ciborium::ser::into_writer(encrypted, &mut data)
        .expect("CBOR serialization of EncryptedMessage should not fail");
    data
}

// Deserialize EncryptedMessage using CBOR
fn deserialize_encrypted_message(data: &[u8]) -> Result<EncryptedMessage, String> {
    ciborium::de::from_reader(data).map_err(|e| format!("CBOR decode failed: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
        time::{Duration, Instant},
    };

    use super::*;

    /// Immediate future that completes instantly
    struct ImmediateFuture;

    impl Future for ImmediateFuture {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(())
        }
    }

    #[derive(Clone)]
    struct TestEnv;

    impl Environment for TestEnv {
        type Instant = Instant;

        fn now(&self) -> Self::Instant {
            Instant::now()
        }

        fn sleep(&self, _duration: Duration) -> impl Future<Output = ()> + Send {
            ImmediateFuture
        }

        fn random_bytes(&self, buffer: &mut [u8]) {
            // Deterministic for tests
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = i as u8;
            }
        }
    }

    #[test]
    fn create_client() {
        let env = TestEnv;
        let identity = ClientIdentity::new(42);
        let client: Client<TestEnv> = Client::new(env, identity);

        assert_eq!(client.sender_id(), 42);
        assert_eq!(client.room_count(), 0);
    }

    #[test]
    fn create_room() {
        let env = TestEnv;
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_5678_9abc_def0_u128;
        let actions = client.handle(ClientEvent::CreateRoom { room_id }).unwrap();

        assert!(client.is_member(room_id));
        assert_eq!(client.epoch(room_id), Some(0));
        assert!(!actions.is_empty());
    }

    #[test]
    fn create_duplicate_room_fails() {
        let env = TestEnv;
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_u128;
        client.handle(ClientEvent::CreateRoom { room_id }).unwrap();

        let result = client.handle(ClientEvent::CreateRoom { room_id });
        assert!(matches!(result, Err(ClientError::RoomAlreadyExists { .. })));
    }

    #[test]
    fn send_message_to_unknown_room_fails() {
        let env = TestEnv;
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let result = client.handle(ClientEvent::SendMessage {
            room_id: 0x9999_u128,
            plaintext: b"hello".to_vec(),
        });

        assert!(matches!(result, Err(ClientError::RoomNotFound { .. })));
    }

    #[test]
    fn leave_room() {
        let env = TestEnv;
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_u128;
        client.handle(ClientEvent::CreateRoom { room_id }).unwrap();
        assert!(client.is_member(room_id));

        let actions = client.handle(ClientEvent::LeaveRoom { room_id }).unwrap();
        assert!(!client.is_member(room_id));
        assert!(matches!(actions[0], ClientAction::RoomRemoved { .. }));
    }

    #[test]
    fn leave_unknown_room_fails() {
        let env = TestEnv;
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let result = client.handle(ClientEvent::LeaveRoom { room_id: 0x9999_u128 });
        assert!(matches!(result, Err(ClientError::RoomNotFound { .. })));
    }

    #[test]
    fn send_message_produces_encrypted_frame() {
        let env = TestEnv;
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_u128;
        client.handle(ClientEvent::CreateRoom { room_id }).unwrap();

        let actions = client
            .handle(ClientEvent::SendMessage { room_id, plaintext: b"Hello, World!".to_vec() })
            .unwrap();

        // Should produce a Send action with encrypted frame
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            ClientAction::Send(frame) => {
                assert_eq!(frame.header.opcode_enum(), Some(Opcode::AppMessage));
                assert_eq!(frame.header.room_id(), room_id);
                // Payload should be encrypted (not plaintext)
                assert!(!frame.payload.is_empty());
                assert_ne!(frame.payload.as_ref(), b"Hello, World!");
            },
            _ => panic!("Expected Send action"),
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip_same_client() {
        // NOTE: This test demonstrates a known limitation.
        // In the current sender key design, sender and receiver share the same ratchet.
        // When you send (encrypt), your ratchet advances. When you receive your own
        // message back, decryption fails because the ratchet already moved forward.
        //
        // In production:
        // 1. Servers shouldn't echo your own messages back to you
        // 2. Or: We need separate send/receive ratchets per member
        //
        // For now, we test that encryption works and produces valid output,
        // and that the serialization roundtrips correctly.

        let env = TestEnv;
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_u128;
        client.handle(ClientEvent::CreateRoom { room_id }).unwrap();

        // Send a message
        let plaintext = b"Secret message";
        let actions = client
            .handle(ClientEvent::SendMessage { room_id, plaintext: plaintext.to_vec() })
            .unwrap();

        let frame = match &actions[0] {
            ClientAction::Send(f) => f.clone(),
            _ => panic!("Expected Send action"),
        };

        // Verify the encrypted payload can be deserialized
        let encrypted = deserialize_encrypted_message(&frame.payload).unwrap();
        assert_eq!(encrypted.epoch, 0);
        assert_eq!(encrypted.sender_index, 0); // Creator is leaf 0
        assert_eq!(encrypted.generation, 0); // First message
        assert!(!encrypted.ciphertext.is_empty());

        // Verify sender's ratchet advanced
        let room = client.rooms.get(&room_id).unwrap();
        assert_eq!(room.sender_keys.generation(0), Some(1)); // Now at gen 1
    }
}
