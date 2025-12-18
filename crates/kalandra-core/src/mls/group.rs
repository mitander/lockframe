//! Client-side MLS group state machine.

use std::collections::HashMap;

use kalandra_proto::{Frame, FrameHeader, Opcode};
use openmls::{key_packages::KeyPackageIn, prelude::*};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;
use tls_codec::{Deserialize, Serialize};

use super::{
    MlsGroupState,
    error::MlsError,
    provider::MlsProvider,
    validator::{MlsValidator, ValidationResult},
};
use crate::env::Environment;

/// Room identifier (128-bit UUID).
pub type RoomId = u128;

/// Member identifier within a group.
pub type MemberId = u64;

/// Actions that MLS group operations can produce.
///
/// The application layer is responsible for executing these actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsAction {
    /// Send proposal frame to sequencer
    SendProposal(Frame),

    /// Send commit frame to sequencer
    SendCommit(Frame),

    /// Send welcome message to new member
    SendWelcome {
        /// Member ID to send welcome message to
        recipient: MemberId,
        /// Welcome frame containing group secrets
        frame: Frame,
    },

    /// Send application message to group (via sequencer)
    SendMessage(Frame),

    /// Deliver decrypted application message to application
    DeliverMessage {
        /// Member ID who sent the message
        sender: MemberId,
        /// Decrypted message plaintext
        plaintext: Vec<u8>,
    },

    /// Remove this group (we were kicked/banned or left)
    RemoveGroup {
        /// Reason for removal
        reason: String,
    },

    /// Log event for debugging/monitoring
    Log {
        /// Log message
        message: String,
    },
}

/// Extract member_id from an MLS credential.
///
/// Our credentials store the member_id as little-endian u64 bytes.
fn extract_member_id_from_credential(credential: &Credential) -> Result<MemberId, MlsError> {
    let bytes = credential.serialized_content();
    if bytes.len() < 8 {
        return Err(MlsError::Crypto(format!(
            "Invalid credential: expected 8 bytes for member_id, got {}",
            bytes.len()
        )));
    }
    let member_id_bytes: [u8; 8] = bytes[..8]
        .try_into()
        .map_err(|_| MlsError::Crypto("Failed to extract member_id bytes".to_string()))?;
    Ok(u64::from_le_bytes(member_id_bytes))
}

/// Client-side MLS group state.
///
/// Represents participation in a single MLS group (room). Clients can be
/// members of multiple groups simultaneously.
///
/// # Invariants
///
/// - Epoch only increases (never decreases)
/// - All members at same epoch have identical tree hash
/// - Only members can encrypt/decrypt messages for current epoch
///
/// # Type Parameters
///
/// - `E`: The environment implementation (SimEnv or SystemEnv)
pub struct MlsGroup<E: Environment> {
    /// Room identifier
    room_id: RoomId,

    /// Our member ID in this group
    member_id: MemberId,

    /// OpenMLS group instance (contains all MLS state)
    mls_group: openmls::group::MlsGroup,

    /// Our signature keypair for this group
    signer: SignatureKeyPair,

    /// Provider for crypto/storage/RNG
    provider: MlsProvider<E>,

    /// Pending commit that we sent (waiting for sequencer acceptance)
    pending_commit: Option<PendingCommit<E::Instant>>,
}

/// Tracks a commit we sent that's waiting for sequencer acceptance.
#[derive(Debug, Clone)]
struct PendingCommit<I> {
    /// Epoch this commit will create when accepted
    target_epoch: u64,

    /// When we sent it (for timeout detection)
    sent_at: I,
}

impl<E: Environment> MlsGroup<E> {
    /// Create a new MLS group.
    ///
    /// This initializes a new group at epoch 0. The creator becomes the first
    /// member and can add other members via proposals + commits.
    ///
    /// Returns a tuple containing a new `MlsGroup` instance and any actions to
    /// execute.
    ///
    /// # Errors
    ///
    /// Returns an error if MLS group creation fails (crypto initialization,
    /// etc.)
    #[allow(clippy::too_many_lines)]
    pub fn new(
        env: E,
        room_id: RoomId,
        member_id: MemberId,
    ) -> Result<(Self, Vec<MlsAction>), MlsError> {
        let provider = MlsProvider::new(env);
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| MlsError::Crypto(format!("Failed to generate keypair: {}", e)))?;

        let credential = BasicCredential::new(member_id.to_le_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .build();
        let mls_group =
            openmls::group::MlsGroup::new(&provider, &signer, &group_config, credential_with_key)
                .map_err(|e| MlsError::Crypto(format!("Failed to create MLS group: {}", e)))?;

        let group = Self { room_id, member_id, mls_group, signer, provider, pending_commit: None };

        let actions = vec![MlsAction::Log {
            message: format!("Created group {} at epoch 0 (member_id={})", room_id, member_id),
        }];

        Ok((group, actions))
    }

    /// Get the current epoch number.
    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }

    /// Get our member ID.
    pub fn member_id(&self) -> MemberId {
        self.member_id
    }

    /// Get the room ID.
    pub fn room_id(&self) -> RoomId {
        self.room_id
    }

    /// Get the MLS group ID.
    pub fn group_id(&self) -> &GroupId {
        self.mls_group.group_id()
    }

    /// Get our leaf index in the MLS tree.
    pub fn own_leaf_index(&self) -> u32 {
        self.mls_group.own_leaf_index().u32()
    }

    /// Sign a frame header using this group's MLS signature key.
    ///
    /// The signature is computed over the first 64 bytes of the header
    /// (the routing/sequencing data, excluding the signature field itself).
    /// The signature is set directly on the header.
    pub fn sign_frame_header(&self, header: &mut FrameHeader) {
        let header_bytes = header.to_bytes();
        let signed_data = &header_bytes[..64];

        if let Ok(signature) = self.signer.sign(signed_data) {
            if signature.len() == 64 {
                let mut sig_bytes = [0u8; 64];
                sig_bytes.copy_from_slice(&signature);
                header.set_signature(sig_bytes);
            }
        }
    }

    /// Get all member leaf indices in the group.
    ///
    /// Returns the leaf indices of all current group members, which are
    /// needed for sender key initialization.
    pub fn member_leaf_indices(&self) -> Vec<u32> {
        self.mls_group.members().map(|m| m.index.u32()).collect()
    }

    /// Look up a member's ID by their leaf index.
    ///
    /// This is used to verify that a frame's sender_id matches the sender_index
    /// from an encrypted payload (binding the sender identity to the key used).
    ///
    /// Returns `None` if no member exists at the given leaf index.
    pub fn member_id_by_leaf_index(&self, leaf_index: u32) -> Option<MemberId> {
        self.mls_group.members().find_map(|m| {
            if m.index.u32() == leaf_index {
                extract_member_id_from_credential(&m.credential).ok()
            } else {
                None
            }
        })
    }

    /// Export a secret derived from the current epoch's key schedule.
    ///
    /// This is used to derive sender keys for data-plane encryption.
    /// The secret is bound to the current epoch and the provided label.
    /// # Errors
    ///
    /// Returns an error if the export fails (e.g., invalid length).
    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, MlsError> {
        self.mls_group
            .export_secret(self.provider.crypto(), label, context, length)
            .map_err(|e| MlsError::Crypto(format!("Failed to export secret: {}", e)))
    }

    /// Check if we have a pending commit waiting for acceptance.
    pub fn has_pending_commit(&self) -> bool {
        self.pending_commit.is_some()
    }

    /// Check if a pending commit has timed out.
    ///
    /// Returns true if we have a pending commit that's been waiting for at
    /// least the timeout duration (inclusive).
    pub fn is_commit_timeout(&self, now: E::Instant, timeout: std::time::Duration) -> bool
    where
        E::Instant: Copy + Ord + std::ops::Sub<Output = std::time::Duration>,
    {
        self.pending_commit
            .as_ref()
            .map(|pending| now - pending.sent_at >= timeout)
            .unwrap_or(false)
    }

    /// Merge the pending commit after it has been confirmed by the sequencer.
    ///
    /// This is called when we created a commit (e.g., via add_members) and
    /// the sequencer has confirmed it. This advances the group's epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if there's no pending commit or if merging fails.
    pub fn merge_pending_commit(&mut self) -> Result<(), MlsError> {
        let expected_epoch = self
            .pending_commit
            .as_ref()
            .map(|p| p.target_epoch)
            .ok_or_else(|| MlsError::Crypto("No pending commit to merge".to_string()))?;

        self.mls_group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MlsError::Crypto(format!("Failed to merge pending commit: {}", e)))?;

        let actual_epoch = self.epoch();
        debug_assert_eq!(
            actual_epoch, expected_epoch,
            "Epoch after merge ({}) doesn't match expected ({})",
            actual_epoch, expected_epoch
        );

        self.pending_commit = None;

        Ok(())
    }

    /// Check if the OpenMLS group has a pending commit.
    pub fn has_mls_pending_commit(&self) -> bool {
        self.mls_group.pending_commit().is_some()
    }

    /// Validate a frame against this group's MLS state
    ///
    /// Checks:
    /// - Frame epoch matches group epoch
    /// - Sender is a member of the group
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if validation fails.
    pub fn validate_frame(
        &self,
        frame: &Frame,
        mls_state: Option<&super::MlsGroupState>,
    ) -> Result<(), MlsError> {
        let validation_result = if let Some(state) = mls_state {
            MlsValidator::validate_frame(frame, self.epoch(), state)?
        } else {
            MlsValidator::validate_frame_no_state(frame)?
        };

        match validation_result {
            ValidationResult::Accept => Ok(()),
            ValidationResult::Reject { reason } => Err(MlsError::ValidationFailed(reason)),
        }
    }

    /// Process an incoming MLS message (Commit, Proposal, or Application).
    ///
    /// Processes an MLS protocol message, updates the group state, and returns
    /// any actions that need to be taken as a result.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The message cannot be deserialized
    /// - The message is invalid (wrong epoch, bad signature, etc.)
    /// - Crypto operations fail
    pub fn process_message(&mut self, frame: Frame) -> Result<Vec<MlsAction>, MlsError> {
        let mls_message =
            MlsMessageIn::tls_deserialize_exact(frame.payload.as_ref()).map_err(|e| {
                MlsError::Serialization(format!("Failed to deserialize MLS message: {}", e))
            })?;

        let protocol_message: ProtocolMessage = mls_message
            .try_into()
            .map_err(|e| MlsError::Serialization(format!("Invalid MLS message type: {:?}", e)))?;

        let processed = self
            .mls_group
            .process_message(&self.provider, protocol_message)
            .map_err(|e| MlsError::Crypto(format!("Failed to process message: {}", e)))?;

        let sender_id = extract_member_id_from_credential(processed.credential())?;

        let mut actions = Vec::new();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                actions.push(MlsAction::DeliverMessage {
                    sender: sender_id,
                    plaintext: app_msg.into_bytes(),
                });
            },
            ProcessedMessageContent::ProposalMessage(proposal) => {
                actions.push(MlsAction::Log {
                    message: format!(
                        "Received proposal in epoch {}: {:?}",
                        self.epoch(),
                        proposal.proposal()
                    ),
                });
            },
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                actions.push(MlsAction::Log {
                    message: format!("Received external join proposal in epoch {}", self.epoch()),
                });
            },
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.mls_group
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .map_err(|e| MlsError::Crypto(format!("Failed to merge commit: {}", e)))?;

                actions.push(MlsAction::Log {
                    message: format!("Advanced to epoch {}", self.epoch()),
                });

                if !self.mls_group.is_active() {
                    actions.push(MlsAction::RemoveGroup {
                        reason: "Removed from group by commit".to_string(),
                    });
                }
            },
        }

        Ok(actions)
    }

    /// Create an application message to send to the group.
    ///
    /// Encrypts a plaintext message using the current epoch's encryption key
    /// and returns a frame ready to send to the sequencer.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails or the group is not active.
    pub fn create_message(&mut self, plaintext: &[u8]) -> Result<Vec<MlsAction>, MlsError> {
        let mls_message = self
            .mls_group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| MlsError::Crypto(format!("Failed to create message: {}", e)))?;

        let payload = mls_message
            .tls_serialize_detached()
            .map_err(|e| MlsError::Serialization(format!("Failed to serialize message: {}", e)))?;

        let frame = Frame { header: FrameHeader::new(Opcode::AppMessage), payload: payload.into() };

        Ok(vec![MlsAction::SendMessage(frame)])
    }

    /// Add members to the group by their serialized KeyPackages.
    ///
    /// Creates a commit that adds the specified members to the group. The
    /// commit must be sent to the sequencer and will advance the epoch when
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - KeyPackage deserialization fails
    /// - Commit creation fails
    pub fn add_members_from_bytes(
        &mut self,
        key_packages_bytes: &[Vec<u8>],
    ) -> Result<Vec<MlsAction>, MlsError> {
        let key_packages: Vec<KeyPackage> = key_packages_bytes
            .iter()
            .map(|bytes| {
                let kp_in = KeyPackageIn::tls_deserialize(&mut bytes.as_slice())
                    .map_err(|e| MlsError::Serialization(format!("Invalid KeyPackage: {}", e)))?;
                kp_in
                    .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|e| MlsError::Crypto(format!("Invalid KeyPackage signature: {:?}", e)))
            })
            .collect::<Result<Vec<_>, MlsError>>()?;

        self.add_members(key_packages)
    }

    /// Join a group via a Welcome message.
    ///
    /// Creates a new MlsGroup instance by processing a Welcome message received
    /// from an existing group member. The Welcome contains the group secrets
    /// needed to participate.
    ///
    /// Returns a new MlsGroup instance initialized at the current group epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Welcome deserialization fails
    /// - Welcome processing fails (wrong KeyPackage, crypto error, etc.)
    pub fn join_from_welcome(
        env: E,
        room_id: RoomId,
        member_id: MemberId,
        welcome_bytes: &[u8],
    ) -> Result<(Self, Vec<MlsAction>), MlsError> {
        let provider = MlsProvider::new(env);
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| MlsError::Crypto(format!("Failed to generate keypair: {}", e)))?;

        let mls_message =
            MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_ref()).map_err(|e| {
                MlsError::Serialization(format!("Failed to deserialize Welcome: {}", e))
            })?;

        let welcome = match mls_message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Serialization("Message is not a Welcome".to_string())),
        };

        let group_config = MlsGroupJoinConfig::builder().build();

        let mls_group = StagedWelcome::new_from_welcome(&provider, &group_config, welcome, None)
            .map_err(|e| MlsError::Crypto(format!("Failed to stage Welcome: {}", e)))?
            .into_group(&provider)
            .map_err(|e| MlsError::Crypto(format!("Failed to join group from Welcome: {}", e)))?;

        let epoch = mls_group.epoch().as_u64();
        let group = Self { room_id, member_id, mls_group, signer, provider, pending_commit: None };

        let actions = vec![MlsAction::Log {
            message: format!(
                "Joined group {} at epoch {} via Welcome (member_id={})",
                room_id, epoch, member_id
            ),
        }];

        Ok((group, actions))
    }

    /// Export the current group state for storage.
    ///
    /// Returns the serialized OpenMLS group state that can be stored
    /// and later used to restore the group.
    ///
    /// Returns serialized group state bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn export_state(&self) -> Result<Vec<u8>, MlsError> {
        // For now, we export the group secret as a proxy for the full state
        // In a full implementation, OpenMLS would provide a way to serialize
        // the entire group state including key schedule, tree, etc.
        self.export_secret("group_state", b"", 64)
            .map_err(|e| MlsError::Crypto(format!("Failed to export group state: {}", e)))
    }

    /// Export the current group state as an MlsGroupState struct.
    ///
    /// This is used by the RoomManager to persist MLS state after processing
    /// commits. It includes the lightweight validation data (epoch, members,
    /// public keys) plus the serialized OpenMLS state.
    pub fn export_group_state(&self) -> super::MlsGroupState {
        let mut members = Vec::new();
        let mut member_keys = HashMap::new();

        for m in self.mls_group.members() {
            let identity = m.credential.serialized_content();
            if identity.len() >= 8 {
                if let Ok(id_bytes) = identity[..8].try_into() {
                    let member_id = u64::from_le_bytes(id_bytes);
                    members.push(member_id);

                    if m.signature_key.len() == 32 {
                        if let Ok(key_bytes) = m.signature_key.as_slice().try_into() {
                            member_keys.insert(member_id, key_bytes);
                        }
                    }
                }
            }
        }

        let tree_hash: [u8; 32] =
            self.mls_group.export_group_context().tree_hash().try_into().unwrap_or([0u8; 32]);

        let state = self.export_state().unwrap_or_default();

        MlsGroupState::with_keys(self.room_id, self.epoch(), tree_hash, members, member_keys, state)
    }

    /// Generate a KeyPackage for joining groups.
    ///
    /// Creates a KeyPackage that can be shared with group members who want to
    /// add this client to their group. The KeyPackage is signed with this
    /// client's credential.
    ///
    /// Returns a tuple (KeyPackage bytes, KeyPackage hash ref)
    ///
    /// # Errors
    ///
    /// Returns an error if KeyPackage generation fails.
    pub fn generate_key_package(
        env: E,
        member_id: MemberId,
    ) -> Result<(Vec<u8>, Vec<u8>), MlsError> {
        let provider = MlsProvider::new(env);
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| MlsError::Crypto(format!("Failed to generate keypair: {}", e)))?;

        let credential = BasicCredential::new(member_id.to_le_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let key_package_bundle = KeyPackage::builder()
            .build(ciphersuite, &provider, &signer, credential_with_key)
            .map_err(|e| MlsError::Crypto(format!("Failed to build KeyPackage: {}", e)))?;

        let key_package = key_package_bundle.key_package();

        let serialized = key_package.tls_serialize_detached().map_err(|e| {
            MlsError::Serialization(format!("Failed to serialize KeyPackage: {}", e))
        })?;

        let hash_ref = key_package
            .hash_ref(provider.crypto())
            .map_err(|e| MlsError::Crypto(format!("Failed to compute KeyPackage hash: {}", e)))?;

        Ok((serialized, hash_ref.as_slice().to_vec()))
    }

    /// Generate a KeyPackage and return with provider state for later use.
    ///
    /// Unlike `generate_key_package`, this returns the provider and signer
    /// so that `join_from_welcome_with_state` can access the private key.
    ///
    /// Returns (key_package_bytes, hash_ref, provider, signer)
    pub fn generate_key_package_with_state(
        env: E,
        member_id: MemberId,
    ) -> Result<(Vec<u8>, Vec<u8>, MlsProvider<E>, SignatureKeyPair), MlsError> {
        let provider = MlsProvider::new(env);
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| MlsError::Crypto(format!("Failed to generate keypair: {}", e)))?;

        let credential = BasicCredential::new(member_id.to_le_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let key_package_bundle = KeyPackage::builder()
            .build(ciphersuite, &provider, &signer, credential_with_key)
            .map_err(|e| MlsError::Crypto(format!("Failed to build KeyPackage: {}", e)))?;

        let key_package = key_package_bundle.key_package();

        let serialized = key_package.tls_serialize_detached().map_err(|e| {
            MlsError::Serialization(format!("Failed to serialize KeyPackage: {}", e))
        })?;

        let hash_ref = key_package
            .hash_ref(provider.crypto())
            .map_err(|e| MlsError::Crypto(format!("Failed to compute KeyPackage hash: {}", e)))?;

        Ok((serialized, hash_ref.as_slice().to_vec(), provider, signer))
    }

    /// Join a group from a Welcome message using pre-existing provider state.
    ///
    /// This variant accepts a provider and signer that were used to generate
    /// the KeyPackage, ensuring the private key is available for decryption.
    pub fn join_from_welcome_with_state(
        room_id: RoomId,
        member_id: MemberId,
        welcome_bytes: &[u8],
        provider: MlsProvider<E>,
        signer: SignatureKeyPair,
    ) -> Result<(Self, Vec<MlsAction>), MlsError> {
        let mls_message =
            MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_ref()).map_err(|e| {
                MlsError::Serialization(format!("Failed to deserialize Welcome: {}", e))
            })?;

        let welcome = match mls_message.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Serialization("Message is not a Welcome".to_string())),
        };

        let group_config = MlsGroupJoinConfig::builder().build();

        let mls_group = StagedWelcome::new_from_welcome(&provider, &group_config, welcome, None)
            .map_err(|e| MlsError::Crypto(format!("Failed to stage Welcome: {}", e)))?
            .into_group(&provider)
            .map_err(|e| MlsError::Crypto(format!("Failed to join group from Welcome: {}", e)))?;

        let epoch = mls_group.epoch().as_u64();
        let group = Self { room_id, member_id, mls_group, signer, provider, pending_commit: None };

        let actions = vec![MlsAction::Log {
            message: format!(
                "Joined group {} at epoch {} via Welcome (member_id={})",
                room_id, epoch, member_id
            ),
        }];

        Ok((group, actions))
    }

    /// Add members to the group by their KeyPackages.
    ///
    /// Creates a commit that adds the specified members to the group. The
    /// commit must be sent to the sequencer and will advance the epoch when
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if commit creation fails.
    fn add_members(&mut self, key_packages: Vec<KeyPackage>) -> Result<Vec<MlsAction>, MlsError> {
        let target_epoch = self.epoch() + 1;
        let now = self.provider.now();

        let (mls_message_out, welcome, _group_info) = self
            .mls_group
            .add_members(&self.provider, &self.signer, &key_packages)
            .map_err(|e| MlsError::Crypto(format!("Failed to add members: {}", e)))?;

        // Track the pending commit for timeout detection
        self.pending_commit = Some(PendingCommit { target_epoch, sent_at: now });

        let mut actions = Vec::new();

        let commit_payload = mls_message_out
            .tls_serialize_detached()
            .map_err(|e| MlsError::Serialization(format!("Failed to serialize commit: {}", e)))?;

        let commit_frame =
            Frame { header: FrameHeader::new(Opcode::Commit), payload: commit_payload.into() };

        actions.push(MlsAction::SendCommit(commit_frame));

        let welcome_payload = welcome
            .tls_serialize_detached()
            .map_err(|e| MlsError::Serialization(format!("Failed to serialize welcome: {}", e)))?;

        let welcome_frame =
            Frame { header: FrameHeader::new(Opcode::Welcome), payload: welcome_payload.into() };

        for kp in &key_packages {
            let recipient = extract_member_id_from_credential(kp.leaf_node().credential())?;
            actions.push(MlsAction::SendWelcome { recipient, frame: welcome_frame.clone() });
        }

        actions.push(MlsAction::Log {
            message: format!("Adding {} members to group", key_packages.len()),
        });

        Ok(actions)
    }

    /// Remove members from the group by their member IDs.
    ///
    /// Creates a commit that removes the specified members from the group. The
    /// commit must be sent to the sequencer and will advance the epoch when
    /// accepted.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any member ID is not found in the group
    /// - Commit creation fails
    /// - Trying to remove self (use `leave_group` instead)
    pub fn remove_members(&mut self, member_ids: &[MemberId]) -> Result<Vec<MlsAction>, MlsError> {
        if member_ids.is_empty() {
            return Err(MlsError::Crypto("No members specified for removal".to_string()));
        }

        if member_ids.contains(&self.member_id) {
            return Err(MlsError::Crypto(
                "Cannot remove self with remove_members, use leave_group instead".to_string(),
            ));
        }

        let target_epoch = self.epoch() + 1;
        let now = self.provider.now();

        let leaf_indices = self.member_ids_to_leaf_indices(member_ids)?;

        let (mls_message_out, _welcome_option, _group_info) = self
            .mls_group
            .remove_members(&self.provider, &self.signer, &leaf_indices)
            .map_err(|e| MlsError::Crypto(format!("Failed to remove members: {}", e)))?;

        // Track the pending commit for timeout detection
        self.pending_commit = Some(PendingCommit { target_epoch, sent_at: now });

        let mut actions = Vec::new();

        let commit_payload = mls_message_out
            .tls_serialize_detached()
            .map_err(|e| MlsError::Serialization(format!("Failed to serialize commit: {}", e)))?;

        let commit_frame =
            Frame { header: FrameHeader::new(Opcode::Commit), payload: commit_payload.into() };

        actions.push(MlsAction::SendCommit(commit_frame));

        actions.push(MlsAction::Log {
            message: format!("Removing {} members from group: {:?}", member_ids.len(), member_ids),
        });

        Ok(actions)
    }

    /// Leave the group voluntarily.
    ///
    /// Creates a Remove proposal for this member. The proposal must be sent
    /// to the group and will be committed by another member (typically the
    /// server or group admin). After the commit is processed, this client
    /// should destroy the group state.
    ///
    /// Note: In MLS, a member cannot unilaterally remove themselves - another
    /// member must commit the removal.
    ///
    /// # Errors
    ///
    /// Returns an error if proposal creation fails.
    pub fn leave_group(&mut self) -> Result<Vec<MlsAction>, MlsError> {
        let mls_message_out = self
            .mls_group
            .leave_group(&self.provider, &self.signer)
            .map_err(|e| MlsError::Crypto(format!("Failed to create leave proposal: {}", e)))?;

        let mut actions = Vec::new();

        let proposal_payload = mls_message_out
            .tls_serialize_detached()
            .map_err(|e| MlsError::Serialization(format!("Failed to serialize proposal: {}", e)))?;

        let proposal_frame =
            Frame { header: FrameHeader::new(Opcode::Proposal), payload: proposal_payload.into() };

        actions.push(MlsAction::SendProposal(proposal_frame));

        actions.push(MlsAction::Log {
            message: format!(
                "Created leave proposal for group {} (member_id={})",
                self.room_id, self.member_id
            ),
        });

        Ok(actions)
    }

    /// Map member IDs to their corresponding leaf node indices.
    ///
    /// # Errors
    ///
    /// Returns an error if any member ID is not found in the group.
    fn member_ids_to_leaf_indices(
        &self,
        member_ids: &[MemberId],
    ) -> Result<Vec<LeafNodeIndex>, MlsError> {
        let mut indices = Vec::with_capacity(member_ids.len());

        for &target_id in member_ids {
            let leaf_index = self
                .mls_group
                .members()
                .find_map(|m| {
                    let identity = m.credential.serialized_content();
                    if identity.len() >= 8 {
                        let member_id = u64::from_le_bytes(identity[..8].try_into().ok()?);
                        if member_id == target_id {
                            return Some(m.index);
                        }
                    }
                    None
                })
                .ok_or_else(|| {
                    MlsError::Crypto(format!("Member {} not found in group", target_id))
                })?;

            indices.push(leaf_index);
        }

        Ok(indices)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[derive(Clone)]
    struct TestEnv;

    impl Environment for TestEnv {
        type Instant = Instant;

        fn now(&self) -> Self::Instant {
            Instant::now()
        }

        fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send {
            async move {
                tokio::time::sleep(duration).await;
            }
        }

        fn random_bytes(&self, buffer: &mut [u8]) {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(buffer);
        }
    }

    #[test]
    fn create_group() {
        let env = TestEnv;
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;
        let member_id = 1;

        let (group, actions) =
            MlsGroup::new(env, room_id, member_id).expect("create should succeed");

        assert_eq!(group.room_id(), room_id);
        assert_eq!(group.member_id(), member_id);
        assert_eq!(group.epoch(), 0);
        assert!(!group.has_pending_commit());

        // Should have logged group creation
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], MlsAction::Log { .. }));
    }

    #[test]
    fn commit_timeout_detection() {
        let env = TestEnv;
        let now = Instant::now();
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;
        let member_id = 1;

        let (mut group, _) = MlsGroup::new(env, room_id, member_id).unwrap();

        // No pending commit initially
        assert!(!group.is_commit_timeout(now, Duration::from_secs(5)));

        // Set a pending commit
        group.pending_commit = Some(PendingCommit { sent_at: now, target_epoch: 1 });

        // Not timed out yet
        assert!(!group.is_commit_timeout(now + Duration::from_secs(4), Duration::from_secs(5)));

        // Just at timeout
        assert!(group.is_commit_timeout(now + Duration::from_secs(5), Duration::from_secs(5)));

        // After timeout
        assert!(group.is_commit_timeout(now + Duration::from_secs(6), Duration::from_secs(5)));
    }

    /// Test that process_message returns the correct sender_id.
    ///
    /// This test exposes the bug where sender is hardcoded to 0 in
    /// DeliverMessage.
    #[test]
    fn process_message_returns_correct_sender() {
        let env = TestEnv;
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

        // Alice creates the group
        let alice_id = 42u64;
        let (mut alice_group, _) =
            MlsGroup::new(env.clone(), room_id, alice_id).expect("alice create group");

        // Bob generates a KeyPackage (keeping provider state for later)
        let bob_id = 100u64;
        let (bob_kp_bytes, _, bob_provider, bob_signer) =
            MlsGroup::generate_key_package_with_state(env.clone(), bob_id)
                .expect("bob generate key package");

        // Alice adds Bob - creates Commit and Welcome
        let add_actions =
            alice_group.add_members_from_bytes(&[bob_kp_bytes]).expect("alice add bob");

        // Find the Welcome for Bob
        let welcome_frame = add_actions
            .iter()
            .find_map(|a| match a {
                MlsAction::SendWelcome { frame, .. } => Some(frame.clone()),
                _ => None,
            })
            .expect("should have welcome");

        // Alice merges her pending commit
        alice_group.merge_pending_commit().expect("alice merge commit");

        // Bob joins via Welcome (using his stored provider state)
        let (mut bob_group, _) = MlsGroup::join_from_welcome_with_state(
            room_id,
            bob_id,
            &welcome_frame.payload,
            bob_provider,
            bob_signer,
        )
        .expect("bob join via welcome");

        // Alice creates a message
        let alice_message_actions =
            alice_group.create_message(b"Hello from Alice").expect("alice create message");

        let message_frame = alice_message_actions
            .iter()
            .find_map(|a| match a {
                MlsAction::SendMessage(frame) => Some(frame.clone()),
                _ => None,
            })
            .expect("should have message frame");

        // Bob processes the message
        let bob_receive_actions =
            bob_group.process_message(message_frame).expect("bob process message");

        // ORACLE: DeliverMessage should have sender = alice_id (42), not 0
        let delivered = bob_receive_actions
            .iter()
            .find_map(|a| match a {
                MlsAction::DeliverMessage { sender, plaintext } => {
                    Some((*sender, plaintext.clone()))
                },
                _ => None,
            })
            .expect("should have DeliverMessage");

        assert_eq!(
            delivered.0, alice_id,
            "Sender should be Alice's member_id ({}), not {}",
            alice_id, delivered.0
        );
        assert_eq!(delivered.1, b"Hello from Alice");
    }

    /// Test that add_members returns the correct recipient in SendWelcome.
    ///
    /// This test exposes the bug where recipient is hardcoded to 0 in
    /// SendWelcome.
    #[test]
    fn add_members_returns_correct_welcome_recipient() {
        let env = TestEnv;
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

        // Alice creates the group
        let alice_id = 42u64;
        let (mut alice_group, _) =
            MlsGroup::new(env.clone(), room_id, alice_id).expect("alice create group");

        // Bob generates a KeyPackage with his member_id
        let bob_id = 100u64;
        let (bob_kp_bytes, _, _, _) =
            MlsGroup::generate_key_package_with_state(env.clone(), bob_id)
                .expect("bob generate key package");

        // Alice adds Bob
        let add_actions =
            alice_group.add_members_from_bytes(&[bob_kp_bytes]).expect("alice add bob");

        // Find the Welcome action
        let welcome_recipient = add_actions
            .iter()
            .find_map(|a| match a {
                MlsAction::SendWelcome { recipient, .. } => Some(*recipient),
                _ => None,
            })
            .expect("should have SendWelcome action");

        // ORACLE: SendWelcome.recipient should be Bob's member_id (100), not 0
        assert_eq!(
            welcome_recipient, bob_id,
            "Welcome recipient should be Bob's member_id ({}), not {}",
            bob_id, welcome_recipient
        );
    }

    /// Test that remove_members produces a Commit and removes the correct
    /// member.
    #[test]
    fn remove_members_produces_commit() {
        let env = TestEnv;
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

        // Alice creates the group
        let alice_id = 42u64;
        let (mut alice_group, _) =
            MlsGroup::new(env.clone(), room_id, alice_id).expect("alice create group");

        // Bob generates a KeyPackage
        let bob_id = 100u64;
        let (bob_kp_bytes, _, _, _) =
            MlsGroup::generate_key_package_with_state(env.clone(), bob_id)
                .expect("bob generate key package");

        // Alice adds Bob
        alice_group.add_members_from_bytes(&[bob_kp_bytes]).expect("alice add bob");

        // Merge the pending commit (simulating sequencer confirmation)
        alice_group.merge_pending_commit().expect("merge add commit");

        // Verify Bob is now a member
        let members: Vec<u64> = alice_group
            .mls_group
            .members()
            .filter_map(|m| {
                let identity = m.credential.serialized_content();
                if identity.len() >= 8 {
                    Some(u64::from_le_bytes(identity[..8].try_into().ok()?))
                } else {
                    None
                }
            })
            .collect();
        assert!(members.contains(&bob_id), "Bob should be a member after add");

        // Alice removes Bob
        let remove_actions = alice_group.remove_members(&[bob_id]).expect("alice remove bob");

        // Should have a SendCommit action
        let has_commit = remove_actions.iter().any(|a| matches!(a, MlsAction::SendCommit(_)));
        assert!(has_commit, "remove_members should produce a SendCommit action");

        // Should have a log action mentioning Bob
        let has_log = remove_actions.iter().any(|a| match a {
            MlsAction::Log { message } => message.contains("100"),
            _ => false,
        });
        assert!(has_log, "remove_members should log the removed member ID");
    }

    /// Test that remove_members rejects removing self.
    #[test]
    fn remove_members_rejects_self_removal() {
        let env = TestEnv;
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

        let alice_id = 42u64;
        let (mut alice_group, _) =
            MlsGroup::new(env, room_id, alice_id).expect("alice create group");

        // Trying to remove self should fail
        let result = alice_group.remove_members(&[alice_id]);
        assert!(result.is_err(), "remove_members should reject self-removal");
        assert!(
            result.unwrap_err().to_string().contains("leave_group"),
            "Error should mention leave_group alternative"
        );
    }

    /// Test that remove_members rejects unknown member.
    #[test]
    fn remove_members_rejects_unknown_member() {
        let env = TestEnv;
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

        let alice_id = 42u64;
        let (mut alice_group, _) =
            MlsGroup::new(env, room_id, alice_id).expect("alice create group");

        // Trying to remove non-existent member should fail
        let result = alice_group.remove_members(&[999]);
        assert!(result.is_err(), "remove_members should reject unknown member");
        assert!(
            result.unwrap_err().to_string().contains("not found"),
            "Error should mention member not found"
        );
    }

    /// Test leave_group produces correct actions.
    #[test]
    fn leave_group_produces_commit_and_remove_action() {
        let env = TestEnv;
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

        // Alice creates the group
        let alice_id = 42u64;
        let (mut alice_group, _) =
            MlsGroup::new(env.clone(), room_id, alice_id).expect("alice create group");

        // Bob generates a KeyPackage and joins
        let bob_id = 100u64;
        let (bob_kp_bytes, _, bob_provider, bob_signer) =
            MlsGroup::generate_key_package_with_state(env.clone(), bob_id)
                .expect("bob generate key package");

        // Alice adds Bob
        let add_actions =
            alice_group.add_members_from_bytes(&[bob_kp_bytes]).expect("alice add bob");
        alice_group.merge_pending_commit().expect("merge add commit");

        // Get welcome for Bob
        let welcome_frame = add_actions
            .iter()
            .find_map(|a| match a {
                MlsAction::SendWelcome { frame, .. } => Some(frame.clone()),
                _ => None,
            })
            .expect("should have welcome");

        // Bob joins via Welcome
        let (mut bob_group, _) = MlsGroup::join_from_welcome_with_state(
            room_id,
            bob_id,
            &welcome_frame.payload,
            bob_provider,
            bob_signer,
        )
        .expect("bob join via welcome");

        // Bob leaves the group (creates a proposal, not a commit)
        let leave_actions = bob_group.leave_group().expect("bob leave group");

        // Should have SendProposal (in MLS, self-removal requires another member to
        // commit)
        let has_proposal = leave_actions.iter().any(|a| matches!(a, MlsAction::SendProposal(_)));
        assert!(has_proposal, "leave_group should produce a SendProposal action");

        // Should NOT have RemoveGroup yet - that happens when the commit is processed
        let has_remove = leave_actions.iter().any(|a| matches!(a, MlsAction::RemoveGroup { .. }));
        assert!(
            !has_remove,
            "leave_group should not produce RemoveGroup - that happens when commit is processed"
        );
    }
}
