//! Client-side MLS group state machine.

use kalandra_proto::Frame;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::{Deserialize, Serialize};

use super::{
    error::MlsError,
    provider::MlsProvider,
    validator::{MlsValidator, ValidationResult},
};
use crate::{env::Environment, storage::Storage};

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
    /// Epoch this commit will create
    #[allow(dead_code)] // Will be used when we implement commit handling
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
    pub fn new(
        env: E,
        room_id: RoomId,
        member_id: MemberId,
        now: E::Instant,
    ) -> Result<(Self, Vec<MlsAction>), MlsError> {
        // `now` is not used yet (pending_commit starts as None), but is correctly typed
        // for future use when we create commits and track their timestamps
        let _ = now;
        let provider = MlsProvider::new(env);
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| MlsError::Crypto(format!("Failed to generate keypair: {}", e)))?;

        let credential = BasicCredential::new(member_id.to_le_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        let group_config = MlsGroupCreateConfig::builder().ciphersuite(ciphersuite).build();
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

    /// Validate a frame against this group's MLS state
    ///
    /// Checks:
    /// - Frame epoch matches group epoch
    /// - Sender is a member of the group
    ///
    /// # Errors
    ///
    /// Returns `MlsError` if validation fails.
    pub fn validate_frame(&self, frame: &Frame, storage: &impl Storage) -> Result<(), MlsError> {
        // Try to load MLS state from storage first
        // If not found (e.g., newly created group), use validate_frame_no_state
        let validation_result = if let Some(mls_state) = storage
            .load_mls_state(self.room_id)
            .map_err(|e| MlsError::Crypto(format!("Failed to load MLS state: {}", e)))?
        {
            MlsValidator::validate_frame(frame, self.epoch(), &mls_state)?
        } else {
            // No MLS state in storage yet - validate without state (epoch 0 check)
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
        // Parse the MLS message from the frame payload
        let mls_message =
            MlsMessageIn::tls_deserialize_exact(frame.payload.as_ref()).map_err(|e| {
                MlsError::Serialization(format!("Failed to deserialize MLS message: {}", e))
            })?;

        // Extract the protocol message
        let protocol_message: ProtocolMessage = mls_message
            .try_into()
            .map_err(|e| MlsError::Serialization(format!("Invalid MLS message type: {:?}", e)))?;

        // Process the message through OpenMLS
        let processed = self
            .mls_group
            .process_message(&self.provider, protocol_message)
            .map_err(|e| MlsError::Crypto(format!("Failed to process message: {}", e)))?;

        let mut actions = Vec::new();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                // Decrypted application message - deliver to application
                actions.push(MlsAction::DeliverMessage {
                    sender: 0, // TODO: Map leaf index to member ID
                    plaintext: app_msg.into_bytes(),
                });
            },
            ProcessedMessageContent::ProposalMessage(proposal) => {
                // Proposal received - log it
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
                // Commit received - merge it to advance the epoch
                self.mls_group
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .map_err(|e| MlsError::Crypto(format!("Failed to merge commit: {}", e)))?;

                actions.push(MlsAction::Log {
                    message: format!("Advanced to epoch {}", self.epoch()),
                });

                // Check if we were removed from the group
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
        // Create application message
        let mls_message = self
            .mls_group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| MlsError::Crypto(format!("Failed to create message: {}", e)))?;

        // Serialize to wire format
        let payload = mls_message
            .tls_serialize_detached()
            .map_err(|e| MlsError::Serialization(format!("Failed to serialize message: {}", e)))?;

        // Create frame with the serialized MLS message
        let frame = Frame {
            header: kalandra_proto::FrameHeader::new(kalandra_proto::Opcode::AppMessage),
            payload: payload.into(),
        };

        Ok(vec![MlsAction::SendMessage(frame)])
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
    pub fn add_members(
        &mut self,
        key_packages: Vec<KeyPackage>,
    ) -> Result<Vec<MlsAction>, MlsError> {
        // Create commit that adds members
        let (mls_message_out, welcome, _group_info) = self
            .mls_group
            .add_members(&self.provider, &self.signer, &key_packages)
            .map_err(|e| MlsError::Crypto(format!("Failed to add members: {}", e)))?;

        let mut actions = Vec::new();

        // Serialize commit message
        let commit_payload = mls_message_out
            .tls_serialize_detached()
            .map_err(|e| MlsError::Serialization(format!("Failed to serialize commit: {}", e)))?;

        let commit_frame = Frame {
            header: kalandra_proto::FrameHeader::new(kalandra_proto::Opcode::Commit),
            payload: commit_payload.into(),
        };

        actions.push(MlsAction::SendCommit(commit_frame));

        // Serialize welcome message
        let welcome_payload = welcome
            .tls_serialize_detached()
            .map_err(|e| MlsError::Serialization(format!("Failed to serialize welcome: {}", e)))?;

        let welcome_frame = Frame {
            header: kalandra_proto::FrameHeader::new(kalandra_proto::Opcode::Welcome),
            payload: welcome_payload.into(),
        };

        // Send welcome to all new members (TODO: track individual recipients)
        for _kp in &key_packages {
            actions.push(MlsAction::SendWelcome { recipient: 0, frame: welcome_frame.clone() });
        }

        actions.push(MlsAction::Log {
            message: format!("Adding {} members to group", key_packages.len()),
        });

        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    // Test environment using system RNG (std::time::Instant)
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
        let now = Instant::now();
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;
        let member_id = 1;

        let (group, actions) =
            MlsGroup::new(env, room_id, member_id, now).expect("create should succeed");

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

        let (mut group, _) = MlsGroup::new(env, room_id, member_id, now).unwrap();

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
}
