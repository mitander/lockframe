//! Sender Keys: Data Plane encryption for high-throughput messaging
//!
//! This module implements the Sender Keys protocol which provides ~100x
//! throughput improvement over pure MLS by separating:
//!
//! - Control Plane (MLS): Membership, key agreement, epoch advancement
//! - Data Plane (Sender Keys): Per-sender symmetric encryption with forward
//!   secrecy
//!
//! # Architecture
//!
//! ```text
//! MLS Epoch Secret
//!        │
//!        ▼ HKDF-Expand
//! SenderKeySeed[sender_index]
//!        │
//!        ▼ Initialize
//! SymmetricRatchet
//!        │
//!        ▼ Advance
//! MessageKey[generation]
//!        │
//!        ▼ Encrypt
//! XChaCha20-Poly1305 Ciphertext
//! ```
//!
//! # Security Properties
//!
//! - Forward Secrecy: Old chain keys are deleted after deriving the next one
//! - Post-Compromise Security: New epoch = new sender keys (via MLS)
//! - Sender Authentication: Each sender has unique keys derived from their
//!   index

pub mod derivation;
pub mod encryption;
pub mod error;
pub mod ratchet;

pub use derivation::derive_sender_key_seed;
pub use encryption::{EncryptedMessage, decrypt_message, encrypt_message};
pub use error::SenderKeyError;
pub use ratchet::{MessageKey, SymmetricRatchet};
