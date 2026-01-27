//! Client state machine.
//!
//! The `Client` is the top-level state machine that manages multiple room
//! memberships and orchestrates MLS operations with sender key encryption.

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use lockframe_core::{
    env::Environment,
    mls::{MlsAction, MlsGroup, PendingJoinState, RoomId},
};
use lockframe_crypto::{EncryptedMessage as CryptoEncryptedMessage, NONCE_RANDOM_SIZE};
use lockframe_proto::{
    Frame, FrameHeader, Opcode, Payload,
    payloads::{
        app::EncryptedMessage,
        mls::{GroupInfoPayload, KeyPackageFetchPayload, KeyPackagePublishRequest},
        session::SyncResponse,
    },
};

use crate::{
    error::ClientError,
    event::{ClientAction, ClientEvent, RoomStateSnapshot},
    sender_key_store::SenderKeyStore,
};

/// Label for MLS secret export (domain separation).
const SENDER_KEY_LABEL: &str = "lockframe sender keys v1";

/// Context for MLS secret export.
const SENDER_KEY_CONTEXT: &[u8] = b"";

/// Size of the sender key secret in bytes.
const SENDER_KEY_SECRET_SIZE: usize = 32;

/// Timeout for pending commits before requesting sync (30 seconds).
const COMMIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for pending `KeyPackage` fetch operations (60 seconds).
const KEY_PACKAGE_FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// Client identity.
///
/// Owns the persistent cryptographic material that identifies this client
/// across all room memberships.
///
/// Note: MLS credential and signer are owned by `MlsGroup` per-room.
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

/// State stored between `KeyPackage` generation and Welcome receipt.
type PendingJoin<E> = PendingJoinState<E>;

/// Client for interacting with `LockFrame` server.
pub struct Client<E: Environment> {
    /// Environment for randomness, timing, etc.
    env: E,

    /// Client identity.
    identity: ClientIdentity,

    /// Active room memberships.
    rooms: HashMap<RoomId, RoomState<E>>,

    /// Pending joins awaiting Welcome frames.
    /// Maps `KeyPackage` hash to pending state.
    pending_joins: HashMap<Vec<u8>, PendingJoin<E>>,

    /// Pending add member operations.
    /// Maps (`room_id`, `user_id`) to timestamp for completing the add.
    pending_adds: HashMap<(RoomId, u64), E::Instant>,

    /// Pending external joins awaiting `GroupInfo` responses.
    pending_external_joins: HashSet<RoomId>,
}

impl<E: Environment> Client<E> {
    /// Create a new client with the given identity.
    pub fn new(env: E, identity: ClientIdentity) -> Self {
        Self {
            env,
            identity,
            rooms: HashMap::new(),
            pending_joins: HashMap::new(),
            pending_adds: HashMap::new(),
            pending_external_joins: HashSet::new(),
        }
    }

    /// Client's stable sender ID used in frame headers.
    pub fn sender_id(&self) -> u64 {
        self.identity.sender_id
    }

    /// Number of active room memberships.
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    /// Check if the client is a member of a room.
    pub fn is_member(&self, room_id: RoomId) -> bool {
        self.rooms.contains_key(&room_id)
    }

    /// Current MLS epoch for a room. `None` if not a member.
    pub fn epoch(&self, room_id: RoomId) -> Option<u64> {
        self.rooms.get(&room_id).map(|r| r.mls_group.epoch())
    }

    /// MLS tree hash for a room. `None` if not a member or export fails.
    ///
    /// Tree hash is a cryptographic commitment to the group's ratchet tree.
    /// All members at the same epoch must have identical tree hashes.
    pub fn tree_hash(&self, room_id: RoomId) -> Option<[u8; 32]> {
        self.rooms
            .get(&room_id)
            .and_then(|r| r.mls_group.export_group_state().ok())
            .map(|state| state.tree_hash)
    }

    /// Member IDs in a room. `None` if not a member or export fails.
    ///
    /// Returns all member IDs (`sender_ids`) currently in the MLS group.
    pub fn member_ids(&self, room_id: RoomId) -> Option<Vec<u64>> {
        self.rooms
            .get(&room_id)
            .and_then(|r| r.mls_group.export_group_state().ok())
            .map(|state| state.members)
    }

    /// Generate a `KeyPackage` for this client to join a room.
    ///
    /// The returned `KeyPackage` should be sent to the room creator who will
    /// add this client via `AddMembers`. The client stores the cryptographic
    /// state internally and uses it when the Welcome message arrives.
    ///
    /// Returns (serialized `KeyPackage` bytes, `KeyPackage` hash ref).
    pub fn generate_key_package(&mut self) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
        let (kp_bytes, hash_ref, pending_state) =
            MlsGroup::generate_key_package(self.env.clone(), self.identity.sender_id)
                .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        self.pending_joins.insert(hash_ref.clone(), pending_state);

        Ok((kp_bytes, hash_ref))
    }

    /// Process an event and return resulting actions.
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
            ClientEvent::RemoveMembers { room_id, member_ids } => {
                self.handle_remove_members(room_id, member_ids)
            },
            ClientEvent::PublishKeyPackage => self.handle_publish_key_package(),
            ClientEvent::FetchAndAddMember { room_id, user_id } => {
                self.handle_fetch_and_add_member(room_id, user_id)
            },
            ClientEvent::ExternalJoin { room_id } => self.handle_external_join(room_id),
        }
    }

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

        let payload_len: u32 = payload
            .len()
            .try_into()
            .map_err(|_| ClientError::InvalidFrame { reason: "Payload too large".to_string() })?;

        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(self.identity.sender_id);
        header.set_epoch(room.mls_group.epoch());
        header.set_payload_size(payload_len);

        room.mls_group.sign_frame_header(&mut header);

        let frame = Frame::new(header, payload);

        Ok(vec![ClientAction::Send(frame)])
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<Vec<ClientAction>, ClientError> {
        let room_id = frame.header.room_id();

        let opcode = frame.header.opcode_enum().ok_or(ClientError::InvalidFrame {
            reason: format!("Unknown opcode: {}", frame.header.opcode()),
        })?;

        match opcode {
            Opcode::HelloReply | Opcode::Pong => {
                // Ignore session-level responses (handled at transport layer)
                Ok(vec![])
            },
            Opcode::Error => Ok(vec![ClientAction::Log {
                message: format!("Server error: room_id={room_id:x}"),
            }]),
            Opcode::AppMessage => self.handle_app_message(room_id, frame),
            Opcode::Commit | Opcode::ExternalCommit => self.handle_commit(room_id, frame),
            Opcode::Welcome => self.handle_welcome(room_id, frame),
            Opcode::SyncResponse => self.handle_sync_response(room_id, frame),
            Opcode::KeyPackageFetch => self.handle_key_package_fetch_response(frame),
            Opcode::GroupInfo => self.handle_group_info_response(frame),
            _ => {
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
        if frame.header.sender_id() == self.identity.sender_id {
            // Skip our own messages - we already have the plaintext locally
            // and our sender ratchet has already advanced past this generation
            return Ok(vec![]);
        }

        let room = self.rooms.get_mut(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;

        let frame_epoch = frame.header.epoch();
        let room_epoch = room.mls_group.epoch();

        if frame_epoch != room_epoch {
            return Ok(vec![
                ClientAction::Log {
                    message: format!(
                        "Epoch mismatch for room {room_id:x}: frame {frame_epoch}, room {room_epoch}. Requesting sync."
                    ),
                },
                ClientAction::RequestSync {
                    room_id,
                    from_epoch: room_epoch,
                    to_epoch: frame_epoch,
                },
            ]);
        }

        let validation_state = room.mls_group.export_validation_state();
        room.mls_group
            .validate_frame(&frame, Some(&validation_state))
            .map_err(|e| ClientError::InvalidFrame { reason: e.to_string() })?;

        let proto_encrypted = deserialize_encrypted_message(&frame.payload)
            .map_err(|e| ClientError::InvalidFrame { reason: e })?;

        // Verify sender_id in header matches the sender_index from the encrypted
        // payload. This prevents forgery where an attacker repackages a message
        // with a different header.
        let header_sender_id = frame.header.sender_id();
        let verified_sender_id = room
            .mls_group
            .member_id_by_leaf_index(proto_encrypted.sender_index)
            .ok_or_else(|| ClientError::InvalidFrame {
                reason: format!(
                    "unknown sender_index {} in encrypted payload",
                    proto_encrypted.sender_index
                ),
            })?;

        if header_sender_id != verified_sender_id {
            return Err(ClientError::InvalidFrame {
                reason: format!(
                    "sender_id mismatch: header claims {}, but sender_index {} belongs to {}",
                    header_sender_id, proto_encrypted.sender_index, verified_sender_id
                ),
            });
        }

        let encrypted = proto_to_crypto_encrypted(&proto_encrypted);
        let plaintext = room.sender_keys.decrypt(&encrypted)?;

        Ok(vec![ClientAction::DeliverMessage {
            room_id,
            sender_id: verified_sender_id,
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
        let is_own_commit = frame.header.sender_id() == self.identity.sender_id;

        let Some(room) = self.rooms.get_mut(&room_id) else {
            return Err(ClientError::RoomNotFound { room_id });
        };

        let mut actions = {
            if is_own_commit && room.mls_group.has_pending_commit() {
                let mls_actions = room
                    .mls_group
                    .merge_pending_commit()
                    .map_err(|e| ClientError::Mls { reason: e.to_string() })?;
                self.convert_mls_actions(room_id, mls_actions)
            } else if is_own_commit && !room.mls_group.has_mls_pending_commit() {
                // The MLS group is already at the committed epoch, so we should
                // skip processing entirely to avoid reinitializing sender keys.
                return Ok(vec![ClientAction::Log {
                    message: format!(
                        "Ignoring own external commit for room {room_id:032x} (already applied)"
                    ),
                }]);
            } else {
                // Process the Commit even if we don't have a pending commit.
                // This handles the race condition where we receive our own Commit back
                // before the original send operation consumed the pending commit.
                let mls_actions = room
                    .mls_group
                    .process_message(frame)
                    .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

                self.convert_mls_actions(room_id, mls_actions)
            }
        };

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

    /// Try to join a room using a pending `KeyPackage` state.
    ///
    /// Tries each pending `KeyPackage` state until one succeeds. On success,
    /// the matching state is consumed. On failure, all tried states are
    /// consumed (caller should generate new `KeyPackages` if needed).
    fn try_join_from_welcome(
        &mut self,
        room_id: RoomId,
        welcome_bytes: &[u8],
    ) -> Result<(MlsGroup<E>, Vec<MlsAction>), ClientError> {
        let pending_hashes: Vec<Vec<u8>> = self.pending_joins.keys().cloned().collect();

        if pending_hashes.is_empty() {
            return Err(ClientError::Mls {
                reason: "No pending KeyPackage state available for Welcome".to_string(),
            });
        }

        let mut last_error = None;

        for hash_ref in pending_hashes {
            if let Some(pending_state) = self.pending_joins.remove(&hash_ref) {
                match MlsGroup::join_from_welcome(
                    room_id,
                    self.identity.sender_id,
                    welcome_bytes,
                    pending_state,
                ) {
                    Ok(result) => {
                        return Ok(result);
                    },
                    Err(e) => {
                        // KeyPackage didn't match this Welcome. State is consumed by
                        // join_from_welcome, so we can't put it back. Try the next one.
                        last_error = Some(e);
                    },
                }
            }
        }

        Err(ClientError::Mls {
            reason: format!(
                "No pending KeyPackage matched this Welcome: {}",
                last_error.map_or_else(|| "unknown".to_string(), |e| e.to_string())
            ),
        })
    }

    /// Handle incoming Welcome frame.
    ///
    /// When we receive a Welcome message from another member (who added us),
    /// we process it to join the group. If no matching `KeyPackage` is
    /// available, emits `KeyPackageNeeded` so the caller can trigger
    /// republishing.
    fn handle_welcome(
        &mut self,
        room_id: RoomId,
        frame: Frame,
    ) -> Result<Vec<ClientAction>, ClientError> {
        if self.rooms.contains_key(&room_id) {
            return Err(ClientError::RoomAlreadyExists { room_id });
        }

        let (mls_group, mls_actions) = match self.try_join_from_welcome(room_id, &frame.payload) {
            Ok(result) => result,
            Err(e) => {
                // No matching KeyPackage - signal caller to republish
                return Ok(vec![
                    ClientAction::Log {
                        message: format!("Welcome for room {room_id:x} failed: {e}"),
                    },
                    ClientAction::KeyPackageNeeded { reason: e.to_string() },
                ]);
            },
        };

        let sender_keys = self.initialize_sender_keys(&mls_group)?;
        let my_leaf_index = mls_group.own_leaf_index();

        let room_state = RoomState { mls_group, sender_keys, my_leaf_index };
        let current_epoch = room_state.mls_group.epoch();

        let mls_state = room_state
            .mls_group
            .export_state()
            .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        let snapshot = crate::event::RoomStateSnapshot {
            room_id,
            epoch: current_epoch,
            mls_state,
            my_leaf_index: room_state.my_leaf_index,
        };

        self.rooms.insert(room_id, room_state);

        let mut actions = self.convert_mls_actions(room_id, mls_actions);
        actions.push(ClientAction::Log { message: format!("Joined room {room_id:x} via Welcome") });
        actions.push(ClientAction::PersistRoom(snapshot));
        actions.push(ClientAction::RequestSync {
            room_id,
            from_epoch: current_epoch,
            to_epoch: current_epoch,
        });

        Ok(actions)
    }

    /// Handle join room request via Welcome message.
    ///
    /// This is the application-initiated join (via `ClientEvent::JoinRoom`).
    /// The Welcome message should have been received out-of-band.
    fn handle_join_room(
        &mut self,
        room_id: RoomId,
        welcome: &[u8],
    ) -> Result<Vec<ClientAction>, ClientError> {
        if self.rooms.contains_key(&room_id) {
            return Err(ClientError::RoomAlreadyExists { room_id });
        }

        let (mls_group, mls_actions) = self.try_join_from_welcome(room_id, welcome)?;

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

    /// Handle sync response from server.
    ///
    /// Processes frames from the sync response in order to catch up
    /// to the server's epoch. Each frame is decoded and processed
    /// sequentially. If `has_more` is true, emits another `RequestSync` action.
    fn handle_sync_response(
        &mut self,
        room_id: RoomId,
        frame: Frame,
    ) -> Result<Vec<ClientAction>, ClientError> {
        let sync_response: SyncResponse =
            ciborium::de::from_reader(&frame.payload[..]).map_err(|e| {
                ClientError::InvalidFrame { reason: format!("Failed to decode SyncResponse: {e}") }
            })?;

        let mut all_actions = Vec::new();

        all_actions.push(ClientAction::Log {
            message: format!(
                "Processing sync response for room {room_id:x}: {} frames, has_more={}, server_epoch={}",
                sync_response.frames.len(),
                sync_response.has_more,
                sync_response.server_epoch
            ),
        });

        for (i, frame_bytes) in sync_response.frames.iter().enumerate() {
            let sync_frame = Frame::decode(frame_bytes).map_err(|e| ClientError::InvalidFrame {
                reason: format!("Failed to decode sync frame {i}: {e}"),
            })?;

            match self.handle_frame(sync_frame) {
                Ok(actions) => all_actions.extend(actions),
                Err(e) => {
                    // Log error but continue processing remaining frames
                    // Some frames might be from epochs we already have
                    all_actions.push(ClientAction::Log {
                        message: format!("Sync frame {i} processing error (may be expected): {e}"),
                    });
                },
            }
        }

        if sync_response.has_more {
            // More frames avaliable
            let current_epoch = self.rooms.get(&room_id).map_or(0, |r| r.mls_group.epoch());

            all_actions.push(ClientAction::RequestSync {
                room_id,
                from_epoch: current_epoch,
                to_epoch: sync_response.server_epoch,
            });

            all_actions.push(ClientAction::Log {
                message: format!(
                    "Sync incomplete, requesting more frames for room {room_id:x} (current epoch: {current_epoch}, target: {})",
                    sync_response.server_epoch
                ),
            });
        } else {
            all_actions.push(ClientAction::Log {
                message: format!(
                    "Sync complete for room {room_id:x}, now at epoch {}",
                    self.rooms.get(&room_id).map_or(0, |r| r.mls_group.epoch())
                ),
            });
        }

        Ok(all_actions)
    }

    /// Handle add members request.
    ///
    /// Adds members to a room using their serialized `KeyPackages`.
    /// Delegates to `MlsGroup::add_members_from_bytes`.
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

    fn handle_remove_members(
        &mut self,
        room_id: RoomId,
        member_ids: Vec<u64>,
    ) -> Result<Vec<ClientAction>, ClientError> {
        let room = self.rooms.get_mut(&room_id).ok_or(ClientError::RoomNotFound { room_id })?;
        let mls_actions = room
            .mls_group
            .remove_members(&member_ids)
            .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        Ok(self.convert_mls_actions(room_id, mls_actions))
    }

    /// Handle publish `KeyPackage` request.
    ///
    /// Generates a `KeyPackage` and sends it to the server registry.
    fn handle_publish_key_package(&mut self) -> Result<Vec<ClientAction>, ClientError> {
        let (kp_bytes, hash_ref) = self.generate_key_package()?;

        let payload = KeyPackagePublishRequest { key_package_bytes: kp_bytes, hash_ref };

        let frame = Payload::KeyPackagePublish(payload)
            .into_frame(FrameHeader::new(Opcode::KeyPackagePublish))
            .map_err(|e| ClientError::InvalidFrame { reason: e.to_string() })?;

        Ok(vec![
            ClientAction::Send(frame),
            ClientAction::Log { message: "Published KeyPackage to server".to_string() },
            ClientAction::KeyPackagePublished,
        ])
    }

    /// Handle fetch and add member request.
    ///
    /// Sends a `KeyPackage` fetch request for the specified user.
    /// When the response arrives, the member will be added to the room.
    fn handle_fetch_and_add_member(
        &mut self,
        room_id: RoomId,
        user_id: u64,
    ) -> Result<Vec<ClientAction>, ClientError> {
        if !self.rooms.contains_key(&room_id) {
            return Err(ClientError::RoomNotFound { room_id });
        }

        self.pending_adds.insert((room_id, user_id), self.env.now());

        let payload =
            KeyPackageFetchPayload { user_id, key_package_bytes: Vec::new(), hash_ref: Vec::new() };

        let frame = Payload::KeyPackageFetch(payload)
            .into_frame(FrameHeader::new(Opcode::KeyPackageFetch))
            .map_err(|e| ClientError::InvalidFrame { reason: e.to_string() })?;

        Ok(vec![ClientAction::Send(frame), ClientAction::Log {
            message: format!("Fetching KeyPackage for user {user_id} to add to room {room_id:x}"),
        }])
    }

    /// Handle `KeyPackage` fetch response.
    ///
    /// Completes a pending add operation by using the fetched `KeyPackage`.
    fn handle_key_package_fetch_response(
        &mut self,
        frame: Frame,
    ) -> Result<Vec<ClientAction>, ClientError> {
        let payload: KeyPackageFetchPayload = ciborium::de::from_reader(&frame.payload[..])
            .map_err(|e| ClientError::InvalidFrame {
                reason: format!("Failed to decode KeyPackageFetch response: {e}"),
            })?;

        if payload.key_package_bytes.is_empty() {
            let matching_entries: Vec<(RoomId, u64)> = self
                .pending_adds
                .keys()
                .filter(|(_, user_id)| *user_id == payload.user_id)
                .copied()
                .collect();

            for (room_id, user_id) in matching_entries {
                self.pending_adds.remove(&(room_id, user_id));
            }

            return Ok(vec![ClientAction::Log {
                message: format!("No KeyPackage found for user {}", payload.user_id),
            }]);
        }

        let matching_entries: Vec<(RoomId, u64)> = self
            .pending_adds
            .keys()
            .filter(|(_, pending_user_id)| *pending_user_id == payload.user_id)
            .copied()
            .collect();

        if matching_entries.is_empty() {
            return Err(ClientError::InvalidFrame {
                reason: format!("No pending add for user {}", payload.user_id),
            });
        }

        let mut actions = Vec::new();
        let key_package_bytes = payload.key_package_bytes;

        for (room_id, user_id) in matching_entries {
            self.pending_adds.remove(&(room_id, user_id));

            let Some(room) = self.rooms.get_mut(&room_id) else {
                actions.push(ClientAction::Log {
                    message: format!("Room {room_id:x} not found for pending add, skipping"),
                });
                continue;
            };

            match room.mls_group.add_members_from_bytes(&[key_package_bytes.clone()]) {
                Ok(mls_actions) => {
                    let mut room_actions = self.convert_mls_actions(room_id, mls_actions);
                    room_actions.push(ClientAction::MemberAdded { room_id, user_id });
                    room_actions.push(ClientAction::Log {
                        message: format!(
                            "Added user {user_id} to room {room_id:x} using fetched KeyPackage"
                        ),
                    });
                    actions.extend(room_actions);
                },
                Err(e) => {
                    actions.push(ClientAction::Log {
                        message: format!("Failed to add user {user_id} to room {room_id:x}: {e}"),
                    });
                },
            }
        }

        Ok(actions)
    }

    /// Handle external join request.
    ///
    /// Sends a `GroupInfoRequest` to the server. When the response arrives,
    /// creates an external commit to join the room.
    fn handle_external_join(&mut self, room_id: RoomId) -> Result<Vec<ClientAction>, ClientError> {
        if self.rooms.contains_key(&room_id) {
            return Err(ClientError::RoomAlreadyExists { room_id });
        }

        self.pending_external_joins.insert(room_id);

        let payload = lockframe_proto::payloads::mls::GroupInfoRequest { room_id };

        let frame = Payload::GroupInfoRequest(payload)
            .into_frame(FrameHeader::new(Opcode::GroupInfoRequest))
            .map_err(|e| ClientError::InvalidFrame { reason: e.to_string() })?;

        Ok(vec![ClientAction::Send(frame), ClientAction::Log {
            message: format!("Requesting GroupInfo to join room {room_id:032x}"),
        }])
    }

    /// Handle `GroupInfo` response.
    ///
    /// Completes a pending external join by creating an external commit.
    fn handle_group_info_response(
        &mut self,
        frame: Frame,
    ) -> Result<Vec<ClientAction>, ClientError> {
        let payload: GroupInfoPayload =
            ciborium::de::from_reader(&frame.payload[..]).map_err(|e| {
                ClientError::InvalidFrame {
                    reason: format!("Failed to decode GroupInfo response: {e}"),
                }
            })?;

        let room_id = payload.room_id;

        if !self.pending_external_joins.remove(&room_id) {
            return Err(ClientError::InvalidFrame {
                reason: format!("No pending external join for room {room_id:032x}"),
            });
        }

        let member_id = self.identity.sender_id;

        let (mls_group, mls_actions) = MlsGroup::join_from_external(
            self.env.clone(),
            room_id,
            member_id,
            &payload.group_info_bytes,
        )
        .map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        let sender_keys = self.initialize_sender_keys(&mls_group)?;
        let my_leaf_index = mls_group.own_leaf_index();
        let epoch = mls_group.epoch();

        let initial_state =
            mls_group.export_state().map_err(|e| ClientError::Mls { reason: e.to_string() })?;

        let room_state = RoomState { mls_group, sender_keys, my_leaf_index };
        self.rooms.insert(room_id, room_state);

        let mut actions = self.convert_mls_actions(room_id, mls_actions);

        actions.push(ClientAction::PersistRoom(RoomStateSnapshot {
            room_id,
            epoch,
            mls_state: initial_state,
            my_leaf_index,
        }));

        actions.push(ClientAction::RoomJoined { room_id, epoch });

        Ok(actions)
    }

    /// Handle tick (timeout processing).
    ///
    /// Checks all rooms for pending commits that have timed out.
    /// Also cleans up stale pending `KeyPackage` fetch operations.
    /// For rooms with timed-out commits, clears the pending state and emits
    /// `RequestSync` actions.
    fn handle_tick(&mut self, now: E::Instant) -> Result<Vec<ClientAction>, ClientError> {
        let mut actions = Vec::new();

        let stale_adds: Vec<(RoomId, u64)> = self
            .pending_adds
            .iter()
            .filter(|((_, _), timestamp)| now - **timestamp > KEY_PACKAGE_FETCH_TIMEOUT)
            .map(|((room_id, user_id), _)| (*room_id, *user_id))
            .collect();

        for (room_id, user_id) in stale_adds {
            // Remove stale pending fetch operations
            if self.pending_adds.remove(&(room_id, user_id)).is_some() {
                actions.push(ClientAction::Log {
                    message: format!(
                        "KeyPackage fetch timeout for user {user_id} in room {room_id:x}, removing pending operation"
                    ),
                });
            }
        }

        for (&room_id, room) in &mut self.rooms {
            if room.mls_group.is_commit_timeout(now, COMMIT_TIMEOUT) {
                let current_epoch = room.mls_group.epoch();
                room.mls_group.clear_pending_commit();

                // Sync MLS group to prevent hanging states
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
                MlsAction::PublishGroupInfo { room_id: info_room_id, epoch, group_info_bytes } => {
                    let payload =
                        GroupInfoPayload { room_id: info_room_id, epoch, group_info_bytes };

                    match Payload::GroupInfo(payload)
                        .into_frame(FrameHeader::new(Opcode::GroupInfo))
                    {
                        Ok(frame) => Some(ClientAction::Send(frame)),
                        Err(e) => Some(ClientAction::Log {
                            message: format!("Failed to create GroupInfo frame: {e:?}"),
                        }),
                    }
                },
                MlsAction::Log { message } => Some(ClientAction::Log { message }),
            })
            .collect()
    }
}

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

fn proto_to_crypto_encrypted(proto: &EncryptedMessage) -> CryptoEncryptedMessage {
    CryptoEncryptedMessage {
        epoch: proto.epoch,
        sender_index: proto.sender_index,
        generation: proto.generation,
        nonce: proto.nonce,
        ciphertext: proto.ciphertext.clone(),
    }
}

fn serialize_encrypted_message(encrypted: &EncryptedMessage) -> Vec<u8> {
    let mut data = Vec::new();
    ciborium::ser::into_writer(encrypted, &mut data)
        .expect("CBOR serialization of EncryptedMessage should not fail");
    data
}

fn deserialize_encrypted_message(data: &[u8]) -> Result<EncryptedMessage, String> {
    ciborium::de::from_reader(data).map_err(|e| format!("CBOR decode failed: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use lockframe_core::env::test_utils::MockEnv;

    use super::*;

    #[test]
    fn create_client() {
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let client: Client<MockEnv> = Client::new(env, identity);

        assert_eq!(client.sender_id(), 42);
        assert_eq!(client.room_count(), 0);
    }

    #[test]
    fn create_room() {
        let env = MockEnv::new();
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
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_u128;
        client.handle(ClientEvent::CreateRoom { room_id }).unwrap();

        let result = client.handle(ClientEvent::CreateRoom { room_id });
        assert!(matches!(result, Err(ClientError::RoomAlreadyExists { .. })));
    }

    #[test]
    fn send_message_to_unknown_room_fails() {
        let env = MockEnv::new();
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
        let env = MockEnv::new();
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
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let result = client.handle(ClientEvent::LeaveRoom { room_id: 0x9999_u128 });
        assert!(matches!(result, Err(ClientError::RoomNotFound { .. })));
    }

    #[test]
    fn send_message_produces_encrypted_frame() {
        let env = MockEnv::new();
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
    fn app_message_with_invalid_signature_is_rejected() {
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_u128;
        client.handle(ClientEvent::CreateRoom { room_id }).unwrap();

        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(room_id);
        header.set_sender_id(99); // Different sender
        header.set_epoch(0);
        let frame = Frame::new(header, Vec::<u8>::new());

        let result = client.handle(ClientEvent::FrameReceived(frame));
        assert!(matches!(result, Err(ClientError::InvalidFrame { .. })));
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

        let env = MockEnv::new();
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

    #[test]
    fn pending_adds_timeout_cleanup() {
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_u128;
        client.handle(ClientEvent::CreateRoom { room_id }).unwrap();

        // Add a pending operation
        let user_id = 123;
        let _actions = client.handle(ClientEvent::FetchAndAddMember { room_id, user_id }).unwrap();

        // Verify pending add exists
        assert!(client.pending_adds.contains_key(&(room_id, user_id)));

        // Simulate time passing beyond timeout
        let now = std::time::Instant::now() + KEY_PACKAGE_FETCH_TIMEOUT + Duration::from_secs(1);
        let actions = client.handle(ClientEvent::Tick { now }).unwrap();

        // Verify pending add was cleaned up
        assert!(!client.pending_adds.contains_key(&(room_id, user_id)));

        // Verify timeout log message was generated
        assert!(actions.iter().any(|action| {
            matches!(action, ClientAction::Log { message } if message.contains("KeyPackage fetch timeout"))
        }));
    }

    #[test]
    fn pending_adds_multiple_rooms_same_user() {
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id1 = 0x1234_u128;
        let room_id2 = 0x5678_u128;
        let user_id = 123;

        client.handle(ClientEvent::CreateRoom { room_id: room_id1 }).unwrap();
        client.handle(ClientEvent::CreateRoom { room_id: room_id2 }).unwrap();

        let _actions1 =
            client.handle(ClientEvent::FetchAndAddMember { room_id: room_id1, user_id }).unwrap();
        let _actions2 =
            client.handle(ClientEvent::FetchAndAddMember { room_id: room_id2, user_id }).unwrap();

        assert!(client.pending_adds.contains_key(&(room_id1, user_id)));
        assert!(client.pending_adds.contains_key(&(room_id2, user_id)));
        assert_eq!(client.pending_adds.len(), 2);

        let payload = KeyPackageFetchPayload {
            user_id,
            key_package_bytes: vec![1, 2, 3, 4],
            hash_ref: vec![5, 6, 7, 8],
        };
        let frame = Payload::KeyPackageFetch(payload)
            .into_frame(FrameHeader::new(Opcode::KeyPackageFetch))
            .unwrap();

        let actions = client.handle(ClientEvent::FrameReceived(frame)).unwrap();

        // Verify both pending adds were cleaned up
        assert!(!client.pending_adds.contains_key(&(room_id1, user_id)));
        assert!(!client.pending_adds.contains_key(&(room_id2, user_id)));
        assert_eq!(client.pending_adds.len(), 0);

        // Verify both rooms were processed and failed with invalid KeyPackage
        assert!(actions.iter().any(|action| {
            matches!(action, ClientAction::Log { message } if
                message.contains(&format!("Failed to add user {user_id} to room {room_id1:x}")))
        }));
        assert!(actions.iter().any(|action| {
            matches!(action, ClientAction::Log { message } if
                message.contains(&format!("Failed to add user {user_id} to room {room_id2:x}")))
        }));

        // Verify exactly 2 failure actions (one for each room)
        let failure_actions: Vec<_> = actions.iter().filter(|action| {
            matches!(action, ClientAction::Log { message } if message.contains("Failed to add user"))
        }).collect();
        assert_eq!(failure_actions.len(), 2);
    }

    #[test]
    fn welcome_without_pending_keypackage_emits_keypackage_needed() {
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        // No pending KeyPackage - client never called generate_key_package

        let room_id = 0x1234_u128;
        let mut header = FrameHeader::new(Opcode::Welcome);
        header.set_room_id(room_id);
        let frame = Frame::new(header, vec![1, 2, 3, 4]); // Dummy welcome payload

        let actions = client.handle(ClientEvent::FrameReceived(frame)).unwrap();

        // Should return KeyPackageNeeded, not an error
        assert!(
            actions.iter().any(|a| matches!(a, ClientAction::KeyPackageNeeded { .. })),
            "Expected KeyPackageNeeded action, got: {actions:?}"
        );

        // Should also log the failure
        assert!(actions.iter().any(|a| matches!(a, ClientAction::Log { message }
            if message.contains("Welcome") && message.contains("failed"))));
    }

    #[test]
    fn welcome_with_wrong_keypackage_emits_keypackage_needed() {
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        // Generate a KeyPackage (creates pending state)
        let (_kp_bytes, _hash_ref) = client.generate_key_package().unwrap();
        assert_eq!(client.pending_joins.len(), 1);

        // Send a Welcome that doesn't match our KeyPackage
        let room_id = 0x1234_u128;
        let mut header = FrameHeader::new(Opcode::Welcome);
        header.set_room_id(room_id);
        let frame = Frame::new(header, vec![1, 2, 3, 4]); // Invalid welcome

        let actions = client.handle(ClientEvent::FrameReceived(frame)).unwrap();

        // Pending state should be consumed (even though it failed)
        assert_eq!(client.pending_joins.len(), 0);

        // Should return KeyPackageNeeded for recovery
        assert!(
            actions.iter().any(|a| matches!(a, ClientAction::KeyPackageNeeded { .. })),
            "Expected KeyPackageNeeded action, got: {actions:?}"
        );
    }

    #[test]
    fn welcome_to_existing_room_returns_error() {
        let env = MockEnv::new();
        let identity = ClientIdentity::new(42);
        let mut client = Client::new(env, identity);

        let room_id = 0x1234_u128;
        client.handle(ClientEvent::CreateRoom { room_id }).unwrap();

        // Try to process Welcome for room we're already in
        let mut header = FrameHeader::new(Opcode::Welcome);
        header.set_room_id(room_id);
        let frame = Frame::new(header, vec![1, 2, 3, 4]);

        let result = client.handle(ClientEvent::FrameReceived(frame));

        // This should be a hard error (protocol violation)
        assert!(matches!(result, Err(ClientError::RoomAlreadyExists { .. })));
    }
}
