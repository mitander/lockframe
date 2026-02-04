//! Application message payload types.
//!
//! These payloads handle user-visible messages: encrypted content, delivery
//! receipts, and reactions.

use serde::{Deserialize, Serialize};

/// Encrypted application message
///
/// Primary message type for user-to-user communication. Messages are encrypted
/// with XChaCha20-Poly1305 using sender keys derived from the MLS epoch secret.
/// The nonce is deterministically derived from (epoch, `sender_index`,
/// generation) plus a random suffix to prevent reuse.
///
/// The epoch, `sender_index`, and generation fields let the receiver derive the
/// correct decryption key from their sender key ratchet state. These duplicate
/// some header fields but are included in the CBOR payload for authenticated
/// binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The MLS epoch this message was encrypted under.
    /// Must match the epoch in the frame header.
    pub epoch: u64,

    /// The sender's leaf index in the MLS tree.
    /// Used to select the correct sender key ratchet.
    pub sender_index: u32,

    /// The ratchet generation (message counter for this sender).
    /// Receivers advance their ratchet to this generation before decrypting.
    pub generation: u32,

    /// Nonce for `XChaCha20` (24 bytes).
    /// Structure: `[epoch:8][sender_index:4][generation:4][random:8]`
    pub nonce: [u8; 24],

    /// Ciphertext including 16-byte Poly1305 authentication tag.
    pub ciphertext: Vec<u8>,

    /// Optional: Push-Carried Ephemeral Keys (PCEK)
    ///
    /// List of encrypted message keys for specific recipients.
    /// Only included for high-priority messages (DMs, mentions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_keys: Option<Vec<PushKey>>,
}

/// Push-Carried Ephemeral Key for a specific recipient
///
/// For high-priority messages (DMs, mentions), the sender can include encrypted
/// message keys for specific recipients. This allows offline devices to decrypt
/// the message via push notifications without fetching the full MLS key
/// schedule.
///
/// # Security
///
/// - Perfect Forward Secrecy: Each message uses an ephemeral X25519 keypair.
///   Compromise of long-term keys does not compromise past messages.
///
/// - Selective Recipients: Only critical recipients receive push keys. Regular
///   group messages rely on the MLS ratchet tree instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushKey {
    /// Recipient device ID
    pub recipient_id: u64,

    /// Encrypted message key (80 bytes: `ephemeral_pk` + `encrypted_key` + tag)
    pub encrypted_key: Vec<u8>,
}

/// Delivery receipt
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Log index of the message being acknowledged
    pub message_log_index: u64,

    /// Type of receipt (delivered, read, etc.)
    pub kind: ReceiptType,

    /// Timestamp in Unix milliseconds since epoch (UTC)
    pub timestamp: u64,
}

/// Receipt type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptType {
    /// Message delivered to device
    Delivered,
    /// Message read by user
    Read,
}

/// Message reaction (emoji, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    /// Log index of the message being reacted to
    pub message_log_index: u64,

    /// Reaction content (e.g., emoji)
    pub content: String,

    /// True to add, false to remove
    pub add: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_message_serde() {
        let msg = EncryptedMessage {
            epoch: 1,
            sender_index: 42,
            generation: 0,
            nonce: [0; 24],
            ciphertext: vec![1, 2, 3, 4],
            push_keys: None,
        };

        let cbor = ciborium::ser::into_writer(&msg, Vec::new());
        assert!(cbor.is_ok());
    }

    #[test]
    fn encrypted_message_round_trip() {
        let original = EncryptedMessage {
            epoch: 42,
            sender_index: 7,
            generation: 100,
            nonce: [0xAB; 24],
            ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8],
            push_keys: None,
        };

        // Encode to CBOR
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&original, &mut encoded).unwrap();

        // Decode back
        let decoded: EncryptedMessage = ciborium::de::from_reader(&encoded[..]).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn receipt_serde() {
        let receipt =
            Receipt { message_log_index: 42, kind: ReceiptType::Read, timestamp: 1_234_567_890 };

        let cbor = ciborium::ser::into_writer(&receipt, Vec::new());
        assert!(cbor.is_ok());
    }
}
