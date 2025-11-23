# Sunder Protocol Specification

**Wire Format:** Raw Binary Header (Big Endian) + CBOR Payload
**Cryptography:** MLS (RFC 9420) + XChaCha20-Poly1305

---

## 1. Protocol Overview

Sunder implements a deterministic, sovereign messaging protocol combining MLS group management with sender-key message encryption. Every operation is cryptographically enforced and forensically auditable.

### 1.0 Wire Format Philosophy

The protocol uses a **hybrid encoding strategy** optimized for the Sequencer's hot path:

1. **Header (128 bytes, Raw Binary):** Fixed-size routing metadata for O(1) zero-copy access
2. **Payload (Variable, CBOR):** Structured content with schema evolution support

**Rationale:** The Sequencer must route 15,000+ frames/sec/room based on `room_id` and `log_index` without deserialization overhead. CBOR's variable-length encoding would require full parsing for routing decisions. Raw binary header enables:

- Zero-copy field extraction via `zerocopy` crate
- Perfect cache-line alignment (2 x 64-byte CPU cache lines)
- Type-safe casting with `#[repr(C)]`
- Deterministic frame boundaries for mmap'd logs

**Cache Line Optimization:** The 128-byte header fits exactly into two 64-byte CPU cache lines:

- **Cache Line 1 (bytes 0-63):** All routing/sequencing data (hot path)
- **Cache Line 2 (bytes 64-127):** Authentication signature (verification path)

This layout minimizes memory bandwidth and maximizes cache locality. The Sequencer can route frames touching only Cache Line 1, while signature verification (which can happen on a separate thread) only fetches Cache Line 2.

### 1.1 Design Invariants

1. **Total Ordering:** Every message has exactly one position in the log
2. **Epoch Monotonicity:** Epochs only increase, never decrease
3. **Cryptographic Authority:** Membership changes require cryptographic proof
4. **Forensic Accountability:** All operations are signed and logged
5. **Deterministic Replay:** Given the same inputs, produce identical outputs

### 1.2 Protocol Layers

```
┌───────────────────────┐
│ Application Messages  │ Layer 5: Chat content
├───────────────────────┤
│ MLS Group Management  │ Layer 4: Membership
├───────────────────────┤
│ Frame Protocol (CBOR) │ Layer 3: Framing
├───────────────────────┤
│ QUIC Streams          │ Layer 2: Transport
├───────────────────────┤
│ UDP Datagrams         │ Layer 1: Network
└───────────────────────┘
```

---

## 2. Wire Format Specification

### 2.1 Frame Structure

Every packet follows this exact structure:

```rust
/// Root frame structure
///
/// Layout: [Header: 128 bytes, Raw Binary] + [Payload: Variable, CBOR]
///
/// CRITICAL: Header MUST be raw binary (Big Endian) for zero-copy routing.
/// The Sequencer reads room_id/log_index directly from the byte stream without
/// deserialization to achieve O(1) routing at 15K+ frames/sec.
///
/// **Cache Line Layout:** The header is carefully structured to fit exactly
/// two 64-byte CPU cache lines for optimal memory bandwidth:
///
/// - **Cache Line 1 (0-63):** Routing/sequencing data (hot path)
/// - **Cache Line 2 (64-127):** Authentication signature (verification path)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct FrameHeader {
    // Protocol identification (8 bytes: 0-7)
    magic: u32,                      // MUST be 0x53554E44 ("SUND" in ASCII)
    version: u8,                     // MUST be 0x01 (version 1)
    flags: u8,                       // Feature flags (see 2.2)
    opcode: u16,                     // Operation code (see 2.3)

    // Request/payload metadata (8 bytes: 8-15)
    request_id: u32,                 // Client-generated nonce (4B sufficient for concurrent requests)
    payload_size: u32,               // Payload size in bytes (max 16MB)

    // Routing context (24 bytes: 16-39)
    room_id: [u8; 16],               // UUIDv4 room identifier
    sender_id: u64,                  // Stable sender identifier

    // Ordering context (16 bytes: 40-55)
    log_index: u64,                  // Global sequence number (server-assigned)
    hlc_timestamp: u64,              // Hybrid logical clock

    // MLS binding (8 bytes: 56-63)
    epoch: u64,                      // Current MLS epoch (uniquely identifies key generation)

    // Authentication (64 bytes: 64-127)
    signature: [u8; 64],             // Ed25519 signature over header + payload
}

/// Complete frame with CBOR payload
struct Frame {
    header: FrameHeader,
    payload: Vec<u8>,                // CBOR-encoded payload
}

impl FrameHeader {
    const SIZE: usize = 128;
    const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16MB

    /// Zero-copy parse from network bytes
    ///
    /// SAFETY: Caller must ensure `bytes.len() >= 128` and proper alignment
    unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        &*(bytes.as_ptr() as *const FrameHeader)
    }

    /// Safe parsing with validation
    fn from_bytes(bytes: &[u8]) -> Result<&Self, Error> {
        if bytes.len() < Self::SIZE {
            return Err(Error::FrameTooShort);
        }

        // SAFETY: We checked the length above
        let header = unsafe { Self::from_bytes_unchecked(bytes) };

        // Validate magic number
        if u32::from_be(header.magic) != 0x53554E44 {
            return Err(Error::InvalidMagic);
        }

        // Validate version
        if header.version != 0x01 {
            return Err(Error::UnsupportedVersion(header.version));
        }

        // Validate payload size
        if u32::from_be(header.payload_size) > Self::MAX_PAYLOAD_SIZE as u32 {
            return Err(Error::PayloadTooLarge);
        }

        Ok(header)
    }

    /// Serialize to Big Endian bytes
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        let mut offset = 0;

        // Write each field in Big Endian
        bytes[offset..offset+4].copy_from_slice(&self.magic.to_be_bytes());
        offset += 4;
        bytes[offset] = self.version;
        offset += 1;
        bytes[offset] = self.flags;
        offset += 1;
        bytes[offset..offset+2].copy_from_slice(&self.opcode.to_be_bytes());
        offset += 2;
        bytes[offset..offset+4].copy_from_slice(&self.request_id.to_be_bytes());
        offset += 4;
        bytes[offset..offset+4].copy_from_slice(&self.payload_size.to_be_bytes());
        offset += 4;
        bytes[offset..offset+16].copy_from_slice(&self.room_id);
        offset += 16;
        bytes[offset..offset+8].copy_from_slice(&self.sender_id.to_be_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.log_index.to_be_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.hlc_timestamp.to_be_bytes());
        offset += 8;
        bytes[offset..offset+8].copy_from_slice(&self.epoch.to_be_bytes());
        offset += 8;
        bytes[offset..offset+64].copy_from_slice(&self.signature);

        bytes
    }

    /// Compute signature over header (excluding signature field) + payload
    ///
    /// CRITICAL: Signatures MUST cover the entire frame to prevent tampering.
    /// The signature field itself is excluded from the hash (chicken-and-egg problem).
    fn sign(&mut self, key: &SigningKey, payload: &[u8]) -> [u8; 64] {
        let mut hasher = Blake3::new();

        // Hash header fields (first 64 bytes, before signature)
        hasher.update(&self.magic.to_be_bytes());
        hasher.update(&[self.version, self.flags]);
        hasher.update(&self.opcode.to_be_bytes());
        hasher.update(&self.request_id.to_be_bytes());
        hasher.update(&self.payload_size.to_be_bytes());
        hasher.update(&self.room_id);
        hasher.update(&self.sender_id.to_be_bytes());
        hasher.update(&self.log_index.to_be_bytes());
        hasher.update(&self.hlc_timestamp.to_be_bytes());
        hasher.update(&self.epoch.to_be_bytes());

        // Hash payload
        hasher.update(payload);

        // Generate signature
        key.sign(&hasher.finalize())
    }

    /// Verify covering signature
    fn verify_signature(&self, key: &VerifyingKey, payload: &[u8]) -> Result<()> {
        let mut hasher = Blake3::new();

        // Hash header fields (Cache Line 1: first 64 bytes, before signature)
        hasher.update(&self.magic.to_be_bytes());
        hasher.update(&[self.version, self.flags]);
        hasher.update(&self.opcode.to_be_bytes());
        hasher.update(&self.request_id.to_be_bytes());
        hasher.update(&self.payload_size.to_be_bytes());
        hasher.update(&self.room_id);
        hasher.update(&self.sender_id.to_be_bytes());
        hasher.update(&self.log_index.to_be_bytes());
        hasher.update(&self.hlc_timestamp.to_be_bytes());
        hasher.update(&self.epoch.to_be_bytes());

        // Hash payload
        hasher.update(payload);

        // Verify signature
        key.verify(&hasher.finalize(), &self.signature)
    }
}

impl Frame {
    /// Total frame size on wire
    fn wire_size(&self) -> usize {
        FrameHeader::SIZE + self.payload.len()
    }

    /// Serialize entire frame to wire format
    fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(self.wire_size());
        wire.extend_from_slice(&self.header.to_bytes());
        wire.extend_from_slice(&self.payload);
        wire
    }

    /// Parse from wire format (zero-copy header)
    fn from_wire(bytes: &[u8]) -> Result<Self, Error> {
        // Parse header
        let header_ref = FrameHeader::from_bytes(bytes)?;
        let header = *header_ref;

        // Extract payload
        let payload_size = u32::from_be(header.payload_size) as usize;
        if bytes.len() < FrameHeader::SIZE + payload_size {
            return Err(Error::FrameTruncated);
        }

        let payload = bytes[FrameHeader::SIZE..FrameHeader::SIZE + payload_size].to_vec();

        Ok(Frame { header, payload })
    }
}

```

### 2.2 Feature Flags

```rust
bitflags! {
    struct FrameFlags: u8 {
        const COMPRESSED = 0b00000001;  // Payload is zstd compressed
        const FRAGMENTED = 0b00000010;  // Part of fragmented message
        const PRIORITY   = 0b00000100;  // High priority delivery
        const FEDERATED  = 0b00001000;  // From federated source
        const EXTERNAL   = 0b00010000;  // External sender (server)
        const EPHEMERAL  = 0b00100000;  // Don't persist
        const REDACTABLE = 0b01000000;  // Can be redacted
        const RESERVED   = 0b10000000;  // Reserved for future
    }
}
```

### 2.3 Operation Codes

```rust
#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum Opcode {
    // Session Management (0x0000-0x00FF)
    Hello          = 0x0001,  // Initial handshake
    HelloReply     = 0x0002,  // Server response
    Goodbye        = 0x0003,  // Graceful disconnect
    Ping           = 0x0004,  // Keepalive
    Pong           = 0x0005,  // Keepalive response
    Error          = 0x00FF,  // Error frame

    // MLS Operations (0x1000-0x1FFF)
    KeyPackage     = 0x1000,  // Upload key package
    Proposal       = 0x1001,  // MLS proposal
    Commit         = 0x1002,  // MLS commit
    Welcome        = 0x1003,  // MLS welcome
    GroupInfo      = 0x1004,  // Group context
    PSKProposal    = 0x1005,  // Pre-shared key
    ReInit         = 0x1006,  // Reinitialize group
    ExternalCommit = 0x1007,  // Server-generated commit

    // Application Messages (0x2000-0x2FFF)
    AppMessage     = 0x2000,  // Encrypted message
    AppReceipt     = 0x2001,  // Delivery receipt
    AppReaction    = 0x2002,  // Message reaction
    AppEdit        = 0x2003,  // Message edit
    AppDelete      = 0x2004,  // Message deletion
    Typing         = 0x2005,  // Typing indicator
    Presence       = 0x2006,  // Online status

    // Moderation (0x3000-0x3FFF)
    Redact         = 0x3000,  // Remove content
    Ban            = 0x3001,  // Ban user
    Unban          = 0x3002,  // Unban user
    Kick           = 0x3003,  // Remove from room
    Mute           = 0x3004,  // Mute user
    Pin            = 0x3005,  // Pin message
    Report         = 0x3006,  // Report content

    // Federation (0x4000-0x4FFF)
    FedAppend      = 0x4000,  // Federated append
    FedSync        = 0x4001,  // Sync request
    FedAck         = 0x4002,  // Federation ack
    FedNack        = 0x4003,  // Federation reject
    FedQuery       = 0x4004,  // Query remote

    // Storage (0x5000-0x5FFF)
    CASPut         = 0x5000,  // Store blob
    CASGet         = 0x5001,  // Retrieve blob
    CASDelete      = 0x5002,  // Delete blob
    CASProof       = 0x5003,  // Storage proof
}
```

---

## 3. Cryptographic Specification

### 3.1 Cipher Suites

Sunder supports two cipher suites for different deployment contexts:

#### Suite 0x0003 (Performance - Default)

| Component     | Algorithm           | Parameters    | Purpose            |
| ------------- | ------------------- | ------------- | ------------------ |
| **HPKE KEM**  | X25519 + ML-KEM-768 | Hybrid 64B    | Key encapsulation  |
| **HPKE AEAD** | ChaCha20-Poly1305   | 12-byte nonce | HPKE encryption    |
| **KDF**       | HKDF-SHA256         | -             | Key derivation     |
| **MAC**       | HMAC-SHA256         | -             | Authentication     |
| **Hash**      | BLAKE3              | 256-bit       | Tree hashing       |
| **Signature** | Ed25519             | 64-byte sig   | Authentication     |
| **Data AEAD** | XChaCha20-Poly1305  | 24-byte nonce | Message encryption |

#### Suite 0x0004 (FIPS Compliance)

| Component     | Algorithm          | Parameters    | Purpose            |
| ------------- | ------------------ | ------------- | ------------------ |
| **HPKE KEM**  | P-384 + ML-KEM-768 | Hybrid 80B    | Key encapsulation  |
| **HPKE AEAD** | AES-256-GCM        | 12-byte nonce | HPKE encryption    |
| **KDF**       | HKDF-SHA384        | -             | Key derivation     |
| **MAC**       | HMAC-SHA384        | -             | Authentication     |
| **Hash**      | SHA-384            | 384-bit       | Tree hashing       |
| **Signature** | ECDSA-P384         | 96-byte sig   | Authentication     |
| **Data AEAD** | AES-256-GCM        | 12-byte nonce | Message encryption |

**Note:** Both suites use hybrid post-quantum KEMs. The classical and PQ secrets are combined as specified in Section 3.2.

### 3.2 Key Derivation

#### MLS to Sender Key Bridge (Hybrid KEM)

The protocol uses a **hybrid key encapsulation mechanism** that combines classical ECDH with post-quantum ML-KEM to provide security against both classical and quantum adversaries.

```rust
/// Derive sender keys from MLS epoch secrets (Hybrid KEM)
///
/// Input: Combined classical and post-quantum shared secrets
fn derive_sender_key(
    classical_secret: &[u8],      // X25519 (32B) or P-384 (48B) ECDH
    pq_secret: &[u8; 32],         // ML-KEM-768 shared secret
    epoch: u64,
    sender_index: u32,
) -> SenderKey {
    // Step 1: Combine the two shared secrets
    // This provides security even if either algorithm is broken
    let combined_secret = kdf_extract(
        concat(
            classical_secret,  // Classical (32 or 48 bytes depending on suite)
            pq_secret          // Post-Quantum (32 bytes)
        )
    );

    // Step 2: Derive sender-specific keys from combined secret
    let mut kdf = Hkdf::<Sha256>::new(None, &combined_secret);

    // Create deterministic context
    let mut context = Vec::with_capacity(16);
    context.extend_from_slice(b"SunderSenderV1");
    context.extend_from_slice(&epoch.to_be_bytes());
    context.extend_from_slice(&sender_index.to_be_bytes());

    // Derive keys
    let mut key_material = [0u8; 64];
    kdf.expand(&context, &mut key_material)
        .expect("valid length");

    SenderKey {
        encryption_key: key_material[..32].try_into().unwrap(),
        authentication_key: key_material[32..].try_into().unwrap(),
    }
}

/// Helper function for KDF extraction
fn kdf_extract(input_key_material: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let (prk, _) = Hkdf::<Sha256>::extract(None, input_key_material);
    let mut output = [0u8; 32];
    output.copy_from_slice(prk.as_slice());
    output
}
```

#### Symmetric Ratchet

```rust
/// Forward-secure message key ratchet
struct SymmetricRatchet {
    chain_key: [u8; 32],
    generation: u32,
}

impl SymmetricRatchet {
    /// Advance ratchet and derive message key
    fn advance(&mut self) -> MessageKey {
        // Derive next chain key
        let mut mac = HmacSha256::new_from_slice(&self.chain_key).unwrap();
        mac.update(b"chain");
        self.chain_key = mac.finalize().into_bytes().into();

        // Derive message key
        let mut mac = HmacSha256::new_from_slice(&self.chain_key).unwrap();
        mac.update(b"message");
        let message_key = mac.finalize().into_bytes();

        self.generation += 1;

        MessageKey {
            key: message_key[..32].try_into().unwrap(),
            generation: self.generation,
        }
    }
}
```

### 3.3 Message Encryption

#### Application Message Structure

```rust
/// Encrypted application message
struct ApplicationMessage {
    // Plaintext header (for routing)
    header: MessageHeader,

    // Encrypted payload
    ciphertext: Vec<u8>,

    // Authentication tag
    tag: [u8; 16],
}

struct MessageHeader {
    epoch: u64,       // MLS epoch
    sender: u32,      // Leaf index
    generation: u32,  // Ratchet generation
    message_type: u8, // Content type
    timestamp: u64,   // HLC timestamp

    /// Ephemeral keys for push notifications (Optional)
    /// Only populated for Mentions/DMs to save bandwidth.
    /// Map<RecipientId, EncryptedMessageKey>
    push_keys: Map<u64, Vec<u8>>,
}

/// Encrypt message with sender key
fn encrypt_message(
    plaintext: &[u8],
    sender_key: &SenderKey,
    header: &MessageHeader,
) -> ApplicationMessage {
    // Generate nonce (24 bytes for XChaCha20)
    let mut nonce = [0u8; 24];
    nonce[..8].copy_from_slice(&header.epoch.to_be_bytes());
    nonce[8..12].copy_from_slice(&header.sender.to_be_bytes());
    nonce[12..16].copy_from_slice(&header.generation.to_be_bytes());

    // Last 8 bytes random
    rand::thread_rng().fill_bytes(&mut nonce[16..]);

    // Encrypt with associated data
    let cipher = XChaCha20Poly1305::new(&sender_key.encryption_key);
    let ciphertext = cipher.encrypt(
        &nonce.into(),
        Payload {
            msg: plaintext,
            aad: &header.encode(),
        }
    ).expect("encryption failed");

    ApplicationMessage {
        header: header.clone(),
        ciphertext: ciphertext[..ciphertext.len()-16].to_vec(),
        tag: ciphertext[ciphertext.len()-16..].try_into().unwrap(),
    }
}
```

### 3.4 MLS Extensions

Sunder defines custom extensions to the MLS KeyPackage (RFC 9420 §12.1).

#### Notification Key Extension (ID: 0x000A)

Required for the Mobile Push Strategy (PCEK). This allows senders to encrypt a notification payload specifically for the recipient's device, bypassing the MLS epoch deadlock.

**CRITICAL SECURITY PROPERTY:** The `NotificationKey` is an **asymmetric keypair** (Curve25519). The private key never leaves the device, and the public key is published in the MLS KeyPackage. This prevents battery drain attacks where malicious group members spam push notifications.

```rust
/// Extension data for KeyPackages
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NotificationKeyExtension {
    /// Curve25519 Public Key (X25519)
    /// Used to encrypt the ephemeral MessageKey in push notifications
    ///
    /// CRITICAL: This is a PUBLIC key. The corresponding PRIVATE key is stored
    /// only on the device (in iOS Keychain / Android Keystore).
    ///
    /// This prevents the "Battery Drain Attack": If this were symmetric (derived
    /// from EpochSecret), any malicious group member could spam millions of push
    /// notifications to all other members, draining their batteries.
    public_key: [u8; 32],
}

/// Device-side: Generate notification keypair (once per device)
fn generate_notification_keypair() -> (PublicKey, PrivateKey) {
    // Generate fresh Curve25519 keypair
    let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = x25519_dalek::PublicKey::from(&private);

    (public, private)
}

/// Sender: Encrypt MessageKey for recipient's device
fn encrypt_for_notification(
    message_key: &[u8; 32],
    recipient_public_key: &[u8; 32],
) -> Vec<u8> {
    // Ephemeral X25519 encryption
    let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    // ECDH shared secret
    let recipient_pk = x25519_dalek::PublicKey::from(*recipient_public_key);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

    // Derive encryption key
    let mut kdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut encryption_key = [0u8; 32];
    kdf.expand(b"PCEKv1", &encryption_key).unwrap();

    // Encrypt MessageKey
    let cipher = ChaCha20Poly1305::new(&encryption_key.into());
    let nonce = [0u8; 12]; // Safe because ephemeral key is single-use
    let ciphertext = cipher.encrypt(&nonce.into(), message_key.as_ref()).unwrap();

    // Return: [ephemeral_public_key (32) | ciphertext (32+16)]
    let mut result = Vec::with_capacity(32 + ciphertext.len());
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&ciphertext);
    result
}

/// Recipient (NSE): Decrypt MessageKey with device private key
fn decrypt_notification_key(
    encrypted_blob: &[u8],
    device_private_key: &[u8; 32],
) -> Result<[u8; 32], Error> {
    if encrypted_blob.len() != 80 {
        return Err(Error::InvalidPCEKBlob);
    }

    // Extract ephemeral public key
    let ephemeral_public = x25519_dalek::PublicKey::from(
        <[u8; 32]>::try_from(&encrypted_blob[0..32])?
    );

    // Reconstruct shared secret
    let device_secret = x25519_dalek::StaticSecret::from(*device_private_key);
    let shared_secret = device_secret.diffie_hellman(&ephemeral_public);

    // Derive decryption key
    let mut kdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut decryption_key = [0u8; 32];
    kdf.expand(b"PCEKv1", &decryption_key).unwrap();

    // Decrypt MessageKey
    let cipher = ChaCha20Poly1305::new(&decryption_key.into());
    let nonce = [0u8; 12];
    let plaintext = cipher.decrypt(&nonce.into(), &encrypted_blob[32..])
        .map_err(|_| Error::PCEKDecryptionFailed)?;

    Ok(plaintext.try_into()?)
}
```

**Security Rationale:**

1. **Battery Drain Prevention:** Only the target device can decrypt its push notification. A malicious group member cannot spam notifications to other members because they don't have the private keys.

2. **Server Rate Limiting:** The server can rate-limit push notifications by sender (because it routes them), preventing abuse even if a compromised client tries to spam.

3. **OS-Level Protection:** The NSE can cheaply verify the notification is for this device without accessing the full MLS tree (which would exceed the 24MB memory limit).

4. **Key Rotation:** If a device is compromised, the user can regenerate a new keypair and publish it in an Update proposal, revoking the old key.

**Trade-offs:**

- **Overhead:** +80 bytes per push notification (ephemeral public key + encrypted MessageKey + tag)
- **Computation:** One X25519 scalar multiplication (negligible on modern devices)

---

## 4. State Machines

### 4.1 Connection State Machine

```rust
#[derive(Debug, Clone, Copy)]
enum ConnectionState {
    /// Initial state
    Disconnected,

    /// Sent Hello, awaiting HelloReply
    Connecting {
        attempt: u8,
        since: Instant,
    },

    /// Established, can send/receive
    Connected {
        session_id: u64,
        established: Instant,
    },

    /// Graceful shutdown initiated
    Disconnecting {
        reason: DisconnectReason,
    },

    /// Connection failed
    Failed {
        error: ErrorCode,
        can_retry: bool,
    },
}

/// State transitions (enforced at compile time)
impl ConnectionState {
    fn transition(&mut self, event: ConnectionEvent) -> Result<()> {
        *self = match (*self, event) {
            (Disconnected, ConnectionEvent::Connect) => {
                Connecting { attempt: 1, since: Instant::now() }
            }
            (Connecting { attempt, .. }, ConnectionEvent::HelloReply(id)) => {
                Connected { session_id: id, established: Instant::now() }
            }
            (Connecting { attempt, since }, ConnectionEvent::Timeout) if attempt < 3 => {
                Connecting { attempt: attempt + 1, since }
            }
            (Connecting { .. }, ConnectionEvent::Timeout) => {
                Failed { error: ErrorCode::Timeout, can_retry: true }
            }
            (Connected { .. }, ConnectionEvent::Disconnect(reason)) => {
                Disconnecting { reason }
            }
            (Connected { .. }, ConnectionEvent::Error(code)) => {
                Failed { error: code, can_retry: false }
            }
            (Disconnecting { .. }, ConnectionEvent::Goodbye) => {
                Disconnected
            }
            _ => return Err(Error::InvalidTransition),
        };
        Ok(())
    }
}
```

### 4.2 MLS State Machine

```rust
/// MLS group state with strict transitions
struct MLSGroupState {
    epoch: u64,
    tree_hash: [u8; 32],
    members: BTreeMap<LeafIndex, Member>,
    pending_commit: Option<PendingCommit>,
}

/// Pending commit tracking
struct PendingCommit {
    proposals: Vec<ProposalRef>,
    epoch_target: u64,
    created_at: Instant,
}

impl MLSGroupState {
    /// Process incoming commit (strict validation)
    fn process_commit(&mut self, commit: &MLSCommit) -> Result<()> {
        // Verify epoch progression
        if commit.epoch != self.epoch + 1 {
            return Err(Error::EpochMismatch {
                expected: self.epoch + 1,
                actual: commit.epoch,
            });
        }

        // Verify tree hash continuity
        let computed_hash = self.compute_tree_hash_after(commit)?;
        if computed_hash != commit.confirmation_tag {
            return Err(Error::TreeHashMismatch);
        }

        // Apply changes
        for proposal in &commit.proposals {
            self.apply_proposal(proposal)?;
        }

        // Update state
        self.epoch = commit.epoch;
        self.tree_hash = computed_hash;
        self.pending_commit = None;

        Ok(())
    }

    /// Apply proposal to tree
    fn apply_proposal(&mut self, proposal: &Proposal) -> Result<()> {
        match proposal {
            Proposal::Add(kp) => {
                let index = self.find_empty_leaf()?;
                self.members.insert(index, Member::from_key_package(kp)?);
            }
            Proposal::Remove(index) => {
                self.members.remove(index)
                    .ok_or(Error::InvalidLeafIndex(*index))?;
            }
            Proposal::Update(index, kp) => {
                let member = self.members.get_mut(index)
                    .ok_or(Error::InvalidLeafIndex(*index))?;
                member.update_key_package(kp)?;
            }
            Proposal::PSK(psk_id) => {
                // Handle pre-shared key proposals
                self.register_psk(psk_id)?;
            }
        }
        Ok(())
    }
}
```

---

## 5. Protocol Operations

### 5.1 Connection Establishment

```
Client                          Server
  │                               │
  ├───Hello ──────────────────────→
  │   version: 0x01               │
  │   capabilities: [...]         │
  │   auth: PrivacyPass           │
  │                               │
  │←─ HelloReply ─────────────────┤
  │   session_id: 0x1234...       │
  │   capabilities: [...]         │
  │   challenge: [32 bytes]       │
  │                               │
  ├── Auth ───────────────────────→
  │   signature: Ed25519(chall)   │
  │   identity: KeyPackage        │
  │                               │
  │←──Ready ──────────────────────┤
  │   groups: [...]               │
  │   catchup_from: log_index     │
  │                               │
```

### 5.2 Message Flow

#### Sending a Message

```rust
/// Client-side message sending
async fn send_message(
    room: &Room,
    content: &str,
) -> Result<()> {
    // 1. Get current sender key
    let sender_key = room.get_sender_key()?;

    // 2. Ratchet forward
    let message_key = sender_key.ratchet.advance();

    // 3. Encrypt content
    let encrypted = encrypt_message(
        content.as_bytes(),
        &message_key,
        &MessageHeader {
            epoch: room.epoch,
            sender: room.my_leaf_index,
            generation: message_key.generation,
            message_type: MessageType::Text as u8,
            timestamp: HybridClock::now(),
        },
    );

    // 4. Create frame header
    let payload = encrypted.encode();
    let mut header = FrameHeader {
        magic: 0x53554E44u32.to_be(),  // "SUND" in Big Endian
        version: 0x01,
        flags: FrameFlags::empty().bits(),
        opcode: Opcode::AppMessage as u16,
        request_id: rand::random(),
        room_id: room.id.as_bytes(),
        sender_id: room.my_id,
        log_index: 0, // Server assigns
        hlc_timestamp: HybridClock::now().0,
        epoch: room.epoch,
        payload_size: (payload.len() as u32).to_be(),
        signature: [0; 64], // Will be computed below
    };

    // 5. Sign frame
    header.signature = header.sign(&room.signing_key, &payload);

    let frame = Frame { header, payload };

    // 6. Send over QUIC stream
    room.connection.send_frame(&frame).await?;

    Ok(())
}
```

#### Receiving a Message

```rust
/// Server-side message processing
async fn process_message(
    frame: Frame,
    room_state: &RoomState,
) -> Result<()> {
    // 1. Verify signature
    frame.verify_signature(&room_state.get_member_key(frame.sender_id)?)?;

    // 2. Check epoch
    if frame.epoch != room_state.epoch {
        return Err(Error::StaleEpoch);
    }

    // 3. Check HLC bounds
    let now = HybridClock::now();
    if frame.hlc_timestamp > now + MAX_CLOCK_SKEW {
        return Err(Error::ClockSkewExceeded);
    }

    // 4. Assign log index
    let log_index = room_state.next_log_index();

    // 5. Persist to log
    room_state.append_to_log(log_index, &frame)?;

    // 6. Broadcast to members
    for member in &room_state.members {
        member.send_frame(&frame).await?;
    }

    Ok(())
}
```

### 5.3 External Commits (Server Authority)

```rust
/// Server-initiated member removal
async fn kick_member(
    room: &mut Room,
    target: LeafIndex,
    reason: &str,
) -> Result<()> {
    // 1. Create remove proposal
    let proposal = Proposal::Remove(target);

    // 2. Generate external commit
    let commit = room.mls_state.create_external_commit(
        vec![proposal],
        &server_credential(),
    )?;

    // 3. Create frame
    let payload = commit.encode();
    let mut header = FrameHeader {
        magic: 0x53554E44u32.to_be(),
        version: 0x01,
        flags: FrameFlags::EXTERNAL.bits(),
        opcode: Opcode::ExternalCommit as u16,
        request_id: 0,
        room_id: room.id.as_bytes(),
        sender_id: SERVER_ID,
        log_index: room.next_log_index(),
        hlc_timestamp: HybridClock::now().0,
        epoch: room.epoch + 1,
        payload_size: (payload.len() as u32).to_be(),
        signature: [0; 64],
    };

    // 4. Sign with server key
    header.signature = header.sign(&server_signing_key(), &payload);

    let frame = Frame { header, payload };

    // 5. Apply to local state
    room.mls_state.process_commit(&commit)?;

    // 6. Persist and broadcast
    room.append_to_log(&frame)?;
    room.broadcast_frame(&frame).await?;

    // 7. Audit log
    audit_log::record(AuditEvent::MemberKicked {
        room: room.id,
        target,
        reason: reason.to_string(),
        epoch: room.epoch,
    });

    Ok(())
}
```

---

## 6. Federation Protocol

### 6.1 Double-Signed Transactions

```rust
/// Federated message structure
struct FederatedFrame {
    /// Transport signature (hub-to-hub)
    hub_signature: HubSignature,

    /// Original frame (user-signed)
    inner_frame: Frame,

    /// Federation metadata
    origin_domain: String,
    forwarded_at: u64,
    hop_count: u8,
}

struct HubSignature {
    hub_id: [u8; 32],
    signature: [u8; 64],
    certificate: X509Certificate,
}

/// Validate federated frame
fn validate_federated(frame: &FederatedFrame) -> Result<()> {
    // 1. Verify hub signature
    frame.hub_signature.verify(&frame.inner_frame)?;

    // 2. Verify certificate chain
    verify_certificate_chain(
        &frame.hub_signature.certificate,
        &frame.origin_domain,
    )?;

    // 3. Verify inner frame signature
    let sender_key = lookup_federated_key(
        &frame.origin_domain,
        frame.inner_frame.sender_id,
    )?;
    frame.inner_frame.verify_signature(&sender_key)?;

    // 4. Check hop limit
    if frame.hop_count > MAX_FEDERATION_HOPS {
        return Err(Error::TooManyHops);
    }

    Ok(())
}
```

### 6.2 Authority Transfer Protocol

Authority migration is a strictly ordered "handover" event, not a consensus vote. The current authority designates its successor, signs a handover certificate, and stops accepting writes.

```rust
/// Room authority management
struct RoomAuthority {
    current_authority: HubId,
    epoch: u64,
    state: AuthorityState, // Active or ReadOnly
}

/// The proof of authority transfer
#[derive(Serialize, Deserialize)]
struct HandoverCertificate {
    old_authority: HubId,
    new_authority: HubId,
    final_epoch: u64,
    timestamp: u64,
    // Signature from the old_authority's Identity Key
    signature: [u8; 64],
}

/// The MLS Commit containing the handover
#[derive(Serialize, Deserialize)]
struct TransferCommit {
    handover: HandoverCertificate,
    new_epoch: u64,
}

impl RoomAuthority {
    /// Execute Stop-the-World Authority Transfer
    async fn transfer_authority(
        &mut self,
        new_hub: HubId
    ) -> Result<()> {
        // 1. Enter Read-Only Mode (Stop the World)
        self.state = AuthorityState::ReadOnly;

        // 2. Create Transfer Proof
        let mut handover = HandoverCertificate {
            old_authority: self.current_authority,
            new_authority: new_hub,
            final_epoch: self.epoch,
            timestamp: SystemTime::now(),
            signature: [0; 64],
        };

        // Sign with the Hub's key
        handover.signature = self.sign(&handover)?;

        // 3. Create the Commit
        let commit = TransferCommit {
            handover,
            new_epoch: self.epoch + 1,
        };

        // 4. Broadcast and Shutdown
        self.broadcast_commit(&commit).await?;

        Ok(())
    }
}
```

---

## 7. Time & Ordering

### 7.1 Hybrid Logical Clocks

```rust
/// HLC implementation (64-bit packed)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct HybridTimestamp(u64);

impl HybridTimestamp {
    /// Pack physical and logical components
    fn new(physical_ms: u64, logical: u16) -> Self {
        // 42 bits physical | 22 bits logical
        assert!(physical_ms < (1 << 42), "physical time overflow");
        assert!(logical < (1 << 22), "logical counter overflow");

        Self((physical_ms << 22) | (logical as u64))
    }

    /// Extract components
    fn physical_ms(&self) -> u64 {
        self.0 >> 22
    }

    fn logical(&self) -> u16 {
        (self.0 & 0x3FFFFF) as u16
    }

    /// Update clock on message receipt
    fn update(&mut self, remote: HybridTimestamp) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let max_physical = now_ms.max(self.physical_ms()).max(remote.physical_ms());

        let logical = if max_physical == now_ms && max_physical > self.physical_ms() {
            // Local clock ahead
            0
        } else if max_physical == self.physical_ms() && max_physical == remote.physical_ms() {
            // All clocks equal
            self.logical().max(remote.logical()) + 1
        } else {
            // Remote clock ahead
            remote.logical() + 1
        };

        *self = HybridTimestamp::new(max_physical, logical);
    }
}
```

### 7.2 Ordering Guarantees

```rust
/// Message ordering with deterministic tiebreaking
#[derive(Debug, Clone, PartialEq, Eq)]
struct MessageOrder {
    hlc: HybridTimestamp,
    sender: u64,
    log_index: u64,
}

impl Ord for MessageOrder {
    fn cmp(&self, other: &Self) -> Ordering {
        // Primary: HLC timestamp
        self.hlc.cmp(&other.hlc)
            // Secondary: Sender ID (deterministic)
            .then_with(|| self.sender.cmp(&other.sender))
            // Tertiary: Log index (ultimate authority)
            .then_with(|| self.log_index.cmp(&other.log_index))
    }
}

impl PartialOrd for MessageOrder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
```

---

## 8. Error Handling

### 8.1 Error Codes

```rust
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
enum ErrorCode {
    // Protocol errors (0x0000-0x00FF)
    InvalidMagic       = 0x0001,
    UnsupportedVersion = 0x0002,
    InvalidFrame       = 0x0003,
    InvalidSignature   = 0x0004,

    // MLS errors (0x0100-0x01FF)
    InvalidEpoch       = 0x0101,
    InvalidTreeHash    = 0x0102,
    InvalidProposal    = 0x0103,
    InvalidCommit      = 0x0104,
    StaleEpoch         = 0x0105,  // Client epoch < server epoch (recoverable)
    FutureEpoch        = 0x0106,  // Client epoch > server epoch (bug)

    // Permission errors (0x0200-0x02FF)
    NotAuthorized      = 0x0201,
    Banned             = 0x0202,
    RateLimited        = 0x0203,
    QuotaExceeded      = 0x0204,

    // State errors (0x0300-0x03FF)
    RoomNotFound       = 0x0301,
    MemberNotFound     = 0x0302,
    MessageNotFound    = 0x0303,
    AlreadyExists      = 0x0304,

    // Federation errors (0x0400-0x04FF)
    FederationDisabled = 0x0401,
    InvalidDomain      = 0x0402,
    HopLimitExceeded   = 0x0403,
    AuthorityMismatch  = 0x0404,
}

/// Error frame structure
struct ErrorFrame {
    code: ErrorCode,
    request_id: u64,          // Original request
    details: String,          // Human-readable
    retry_after: Option<u64>, // Seconds

    // Epoch recovery metadata (only for StaleEpoch errors)
    current_epoch: Option<u64>,  // Server's current epoch
    required_commits: Option<Vec<u64>>, // Epochs client needs to fetch
}

/// Error handling for mobile networks
///
/// CRITICAL: Mobile clients frequently go offline during epoch transitions,
/// causing "Zombie Epoch" scenarios where the client is stuck in an old epoch.
///
/// Without automatic recovery, users see repeated "Message Failed" errors,
/// leading to poor UX and support tickets.
///
/// The server MUST return enough metadata in Error::StaleEpoch for the client
/// to transparently recover without user intervention.
impl ErrorFrame {
    /// Create epoch recovery error
    fn stale_epoch(request_id: u64, current: u64, client: u64) -> Self {
        let missing_epochs: Vec<u64> = (client + 1..=current).collect();

        ErrorFrame {
            code: ErrorCode::StaleEpoch,
            request_id,
            details: format!(
                "Client epoch {} is stale. Server is at epoch {}. Fetch commits: {:?}",
                client, current, missing_epochs
            ),
            retry_after: None, // Client should retry immediately after syncing
            current_epoch: Some(current),
            required_commits: Some(missing_epochs),
        }
    }
}
```

---

## 9. Performance Characteristics

### 9.1 Protocol Overhead

| Operation          | Overhead  | Calculated | Notes                     |
| ------------------ | --------- | ---------- | ------------------------- |
| Frame header       | 128 bytes | Fixed      | Raw Binary (Big Endian)   |
| MLS Commit         | ~2KB      | 1.8KB avg  | For 100 members           |
| Message encryption | 40 bytes  | Fixed      | Tag + nonce (XChaCha20)   |
| Federation wrapper | 200 bytes | 196 bytes  | Double signature          |
| HLC timestamp      | 8 bytes   | Fixed      | 64-bit packed (in header) |
| Signature          | 64 bytes  | Fixed      | Ed25519 (in header)       |

### 9.2 Latency Budget

```
Total E2E latency target: <100ms

Network RTT:         20ms  (typical mobile)
QUIC handshake:      0ms   (0-RTT resumption)
Frame parsing:       1ms
Signature verify:    2ms
MLS processing:      5ms   (commit)
Encryption:          1ms   (XChaCha20)
Database write:      10ms  (Redb fsync)
Broadcast fanout:    20ms  (parallel)
──────────────────────────
Total:               59ms  (41ms margin)
```

---

## 10. Security Considerations

### 10.1 Threat Mitigations

| Threat            | Mitigation        | Implementation        |
| ----------------- | ----------------- | --------------------- |
| Replay attacks    | HLC + nonce       | Unique per message    |
| MITM              | Double signatures | Hub + user auth       |
| Rollback          | Tree hash chain   | Cryptographic binding |
| Exhaustion        | Privacy Pass      | Rate limiting         |
| Quantum           | Algorithm agility | PQC ready             |
| Forensic analysis | Secure deletion   | Zero overwrite        |

### 10.2 Security Boundaries

```
Trust Boundary 1: Client ↔ Server
- Mutual TLS authentication
- Privacy Pass for rate limiting
- Frame signatures

Trust Boundary 2: Server ↔ Server
- X.509 certificates
- DNS verification
- Hub signatures

Trust Boundary 3: User ↔ User
- MLS tree authentication
- End-to-end encryption
- No trust in servers for content
```

---

## References

1. RFC 9420: The Messaging Layer Security (MLS) Protocol
2. RFC 8949: Concise Binary Object Representation (CBOR)
3. RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
4. RFC 9000: QUIC Transport Protocol
5. draft-ietf-mls-extensions: MLS Extensions
6. Hybrid Logical Clocks (Kulkarni et al., 2014)
