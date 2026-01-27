//! Lockframe Cryptographic Primitives
//!
//! Cryptographic building blocks for Lockframe. Pure functions with
//! deterministic outputs. Callers provide random bytes for deterministic
//! testing.
//!
//! # Key Lifecycle
//!
//! This section describes the key hierarchy from MLS epoch secrets to
//! per-message encryption keys. For each MLS epoch, a deterministic
//! sender-specific key is derived, from which a symmetric ratchet produces
//! one-time message keys. Advancing the ratchet on every message provides
//! forward secrecy within the epoch.
//!
//! ```text
//! MLS Epoch Secret
//!        │
//!        ▼
//! HKDF → Sender Key (per epoch, per sender)
//!        │
//!        ▼
//! Symmetric Ratchet → Message Keys
//!        │
//!        ▼
//! AEAD Encryption → Ciphertext
//! ```
//!
//! Message keys are used for exactly one encryption operation and are
//! immediately discarded after use, ensuring that past messages remain
//! secure even if later keys are compromised.
//!
//! # Security
//!
//! Forward Secrecy:
//! - MLS epoch rotation: New epoch secret invalidates all previous keys
//! - Ratchet advancement: Old chain keys are zeroized after deriving next key
//! - Message key disposal: Keys are zeroized immediately after single use
//!
//! Sender Isolation:
//! - Each sender has unique keys derived from their `sender_index`
//! - Compromising one sender's ratchet doesn't expose other senders' messages
//! - MLS provides sender authentication at the control plane level
//!
//! Authenticity:
//! - XChaCha20-Poly1305 AEAD provides tamper-proof encryption
//! - Nonce structure binds message to (epoch, sender, generation)
//! - Failed authentication tag -> reject message
//!
//! Post-Compromise Security:
//! - MLS commit advances epoch -> new epoch secret
//! - New epoch secret -> all sender keys re-derived from scratch
//! - Previous compromise doesn't affect new epoch's messages

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod sender_keys;

pub use sender_keys::{
    EncryptedMessage, MessageKey, NONCE_RANDOM_SIZE, SenderKeyError, SymmetricRatchet,
    decrypt_message, derive_sender_key_seed, encrypt_message,
};
