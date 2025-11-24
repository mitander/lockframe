# Client Design Document

## 1. Client Architecture

### 1.1 Core Design

Thick Rust core with thin platform bindings:

```rust
pub struct ClientCore {
    /// MLS state machine
    mls_engine: MLSEngine,

    /// Derived sender keys
    sender_keys: SenderKeyStore,

    /// Message queue
    outbox: MessageQueue,

    /// Sync state
    sync_state: SyncState,
}

/// Platform-specific shell
#[cfg(target_os = "ios")]
pub struct IOSClient {
    core: Arc<ClientCore>,
    database: SQLCipher,
    notification_handler: APNSHandler,
}
```

### 1.2 Memory Model

Static allocations for predictable performance:

```rust
/// Fixed-size allocator for crypto operations
struct CryptoAllocator {
    /// Pre-allocated MLS tree (max 10K members)
    tree_buffer: Box<[u8; MLS_TREE_MAX_SIZE]>,

    /// Sender key cache (LRU, 256 entries)
    key_cache: ArrayVec<SenderKey, 256>,

    /// Message buffers (for regular text messages)
    message_pool: Pool<[u8; MESSAGE_MAX_SIZE]>,
}

const MLS_TREE_MAX_SIZE: usize = 2 * 1024 * 1024;  // 2MB
const MESSAGE_MAX_SIZE: usize = 16 * 1024;         // 16KB (regular app messages)

// Note: Large payloads (media, CAS) use streaming or heap allocation to match
// the protocol's 16MB limit (FrameHeader::MAX_PAYLOAD_SIZE). The MESSAGE_MAX_SIZE
// pool is optimized for frequent text messages, not bulk transfers.
```

#### Panic Handling Strategy

Rust panics can dump memory (including cryptographic keys) to disk via core dumps or logs. To prevent key leakage through crash artifacts:

```toml
# Cargo.toml
[profile.release]
panic = "abort"  # Prevent stack unwinding which might leak secrets in core dumps
opt-level = 3
lto = true
codegen-units = 1
strip = true
```

**Security Rationale:**

- `panic = "abort"` prevents unwinding, which can leave sensitive data in crash logs
- Stack unwinding during panics can expose key material in memory dumps
- Aborting immediately terminates the process without generating detailed backtraces

#### Memory Hygiene

All cryptographic key structures MUST use the `zeroize` crate to ensure memory is scrubbed on drop:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sender key with automatic zeroing
#[derive(Zeroize, ZeroizeOnDrop)]
struct SenderKey {
    #[zeroize(skip)]  // Don't zeroize non-sensitive fields
    generation: u32,

    // These will be zeroed when dropped
    encryption_key: [u8; 32],
    authentication_key: [u8; 32],
}

/// MLS private key material
#[derive(Zeroize, ZeroizeOnDrop)]
struct MLSPrivateKey {
    key_data: Vec<u8>,
}

impl Drop for MLSPrivateKey {
    fn drop(&mut self) {
        // Explicit zeroing (belt-and-suspenders with ZeroizeOnDrop)
        self.zeroize();
    }
}
```

**Why this matters:**

1. **Memory Forensics:** Prevents key extraction from memory dumps or swap files
2. **Use-After-Free Protection:** Ensures stale memory doesn't contain keys
3. **Cold Boot Attacks:** Reduces the window for RAM extraction attacks
4. **Crash Analysis:** Prevents keys from appearing in crash reports sent to monitoring services

---

## 2. Storage Layer

### 2.1 Database Schema

```sql
-- SQLCipher configuration
PRAGMA key = 'x''||hex(key_material);
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 256000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
PRAGMA secure_delete = ON;
PRAGMA foreign_keys = ON;

-- Identity table
CREATE TABLE identity (
    id INTEGER PRIMARY KEY,
    identity_key BLOB NOT NULL,      -- ML-DSA-65 private key
    signing_key BLOB NOT NULL,       -- Ed25519 private key
    created_at INTEGER NOT NULL
);

-- MLS groups
CREATE TABLE groups (
    room_id BLOB PRIMARY KEY,        -- 16 bytes
    tree_data BLOB NOT NULL,         -- Serialized MLS tree
    epoch INTEGER NOT NULL,
    tree_hash BLOB NOT NULL,         -- 32 bytes
    my_leaf_index INTEGER,
    updated_at INTEGER NOT NULL
);

-- Sender keys (derived from MLS)
CREATE TABLE sender_keys (
    room_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    sender_index INTEGER NOT NULL,
    key_data BLOB NOT NULL,          -- 32 bytes
    generation INTEGER DEFAULT 0,
    PRIMARY KEY (room_id, epoch, sender_index)
) WITHOUT ROWID;

-- Separate keys from content locally too
CREATE TABLE payload_keys (
    room_id BLOB NOT NULL,
    log_index INTEGER NOT NULL,
    key_data BLOB NOT NULL, -- The unique key for this specific message
    PRIMARY KEY (room_id, log_index)
);

-- Content is encrypted with the key above (Double Encryption: SenderKey wraps PayloadKey, PayloadKey wraps Content)
CREATE TABLE message_payloads (
    room_id BLOB NOT NULL,
    log_index INTEGER NOT NULL,
    ciphertext BLOB,
    PRIMARY KEY (room_id, log_index)
);

-- Messages
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id BLOB NOT NULL,
    log_index INTEGER NOT NULL,
    sender_index INTEGER NOT NULL,
    hlc_timestamp INTEGER NOT NULL,
    content BLOB,                    -- Decrypted
    type INTEGER NOT NULL,           -- 0=text, 1=media, 2=tombstone
    status INTEGER NOT NULL,         -- 0=pending, 1=sent, 2=delivered
    UNIQUE(room_id, log_index)
);

-- Optimized indices
CREATE INDEX idx_messages_timeline ON messages(room_id, hlc_timestamp DESC);
CREATE INDEX idx_messages_status ON messages(room_id, status) WHERE status = 0;
```

### 2.2 Transaction Patterns

```rust
/// Atomic message processing with Local Crypto-Erasure
fn process_received_message(
    &self,
    envelope: MessageEnvelope,
) -> Result<()> {
    let mut conn = self.db.connection()?;
    let tx = conn.transaction()?;

    // 1. Retrieve Sender Key (MLS derivation)
    let sender_key = tx.prepare_cached(
        "SELECT key_data FROM sender_keys
         WHERE room_id = ?1 AND epoch = ?2 AND sender_index = ?3"
    )?.query_row(
        params![envelope.room_id, envelope.epoch, envelope.sender_index],
        |row| row.get::<_, Vec<u8>>(0)
    )?;

    // 2. Decrypt Transport Layer (E2EE)
    // This gives us the raw plaintext in memory
    let plaintext = decrypt_message(&envelope.ciphertext, &sender_key)?;

    // 3. Prepare for Local Storage (Crypto-Erasure)
    // Generate a random 32-byte key for this specific message
    let local_payload_key = crate::crypto::generate_random_key();

    // Re-encrypt the plaintext with this local key
    let storage_ciphertext = crate::crypto::encrypt_local(&plaintext, &local_payload_key)?;

    // 4. Write to Split Tables (Atomic Insert)

    // A. Insert the Erasure Key
    tx.prepare_cached(
        "INSERT INTO payload_keys (room_id, log_index, key_data)
         VALUES (?1, ?2, ?3)"
    )?.execute(params![
        envelope.room_id,
        envelope.log_index,
        local_payload_key
    ])?;

    // B. Insert the Encrypted Content
    tx.prepare_cached(
        "INSERT INTO message_payloads (room_id, log_index, ciphertext)
         VALUES (?1, ?2, ?3)"
    )?.execute(params![
        envelope.room_id,
        envelope.log_index,
        storage_ciphertext
    ])?;

    // C. Insert Metadata
    // Note: 'content' is set to NULL because data lives in message_payloads
    tx.prepare_cached(
        "INSERT INTO messages (room_id, log_index, sender_index,
                               hlc_timestamp, content, type, status)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, 2)
         ON CONFLICT(room_id, log_index) DO NOTHING"
    )?.execute(params![
        envelope.room_id,
        envelope.log_index,
        envelope.sender_index,
        envelope.hlc_timestamp,
        envelope.message_type,
    ])?;

    // 5. Update Sender Key Generation (Ratchet forward)
    tx.prepare_cached(
        "UPDATE sender_keys SET generation = generation + 1
         WHERE room_id = ?1 AND epoch = ?2 AND sender_index = ?3"
    )?.execute(params![
        envelope.room_id,
        envelope.epoch,
        envelope.sender_index
    ])?;

    tx.commit()?;
    Ok(())
}
```

---

## 3. MLS Integration

### 3.1 State Management

```rust
/// MLS state machine
pub struct MLSEngine {
    /// Active groups
    groups: HashMap<RoomId, MLSGroup>,

    /// Key packages for joining
    key_packages: Vec<KeyPackage>,

    /// Credential
    credential: Credential,

    /// Update entropy tracking (for aggressive healing)
    update_tracker: HashMap<RoomId, UpdateTracker>,
}

/// Tracks when to trigger updates for post-compromise security
struct UpdateTracker {
    messages_since_update: u32,
    last_update: Instant,
    update_threshold_messages: u32,  // Default: 10
    update_threshold_time: Duration,  // Default: 1 hour
}

impl UpdateTracker {
    /// Check if an update should be triggered
    fn should_update(&self) -> bool {
        self.messages_since_update >= self.update_threshold_messages ||
        self.last_update.elapsed() >= self.update_threshold_time
    }

    fn reset(&mut self) {
        self.messages_since_update = 0;
        self.last_update = Instant::now();
    }
}

impl MLSEngine {
    /// Process MLS commit
    pub fn process_commit(
        &mut self,
        room_id: RoomId,
        commit: MLSCommit,
    ) -> Result<EpochChange> {
        let group = self.groups.get_mut(&room_id)
            .ok_or(Error::GroupNotFound)?;

        // Validate epoch progression
        if commit.epoch != group.epoch() + 1 {
            return Err(Error::InvalidEpoch {
                expected: group.epoch() + 1,
                actual: commit.epoch,
            });
        }

        // Process commit
        let staged = group.stage_commit(&commit)?;
        let epoch_secrets = group.merge_staged_commit(staged)?;

        // Derive sender keys
        let sender_keys = derive_sender_keys(&epoch_secrets)?;

        // Reset update tracker (we just got fresh keys)
        if let Some(tracker) = self.update_tracker.get_mut(&room_id) {
            tracker.reset();
        }

        Ok(EpochChange {
            new_epoch: commit.epoch,
            tree_hash: group.tree_hash(),
            sender_keys,
            removed_members: commit.removed_members(),
        })
    }

    /// Send message with automatic healing (aggressive PCS)
    pub async fn send_message_with_healing(
        &mut self,
        room_id: RoomId,
        content: &[u8],
    ) -> Result<()> {
        // Check if we should piggyback an update
        let should_update = self.update_tracker
            .get(&room_id)
            .map(|t| t.should_update())
            .unwrap_or(false);

        if should_update {
            // Create update proposal for our leaf
            let update = self.create_leaf_update(room_id)?;
            self.send_proposal(room_id, update).await?;

            // Reset tracker
            if let Some(tracker) = self.update_tracker.get_mut(&room_id) {
                tracker.reset();
            }
        }

        // Send the actual message
        self.send_message_internal(room_id, content).await?;

        // Increment message counter
        if let Some(tracker) = self.update_tracker.get_mut(&room_id) {
            tracker.messages_since_update += 1;
        }

        Ok(())
    }

    /// Create leaf update proposal for post-compromise security
    fn create_leaf_update(&mut self, room_id: RoomId) -> Result<Proposal> {
        let group = self.groups.get_mut(&room_id)
            .ok_or(Error::GroupNotFound)?;

        // Generate fresh key material
        let new_leaf_node = group.create_update_proposal()?;

        Ok(Proposal::Update(new_leaf_node))
    }
}
```

#### Aggressive Healing Strategy (Post-Compromise Security)

**Problem:** The original guidance of "daily updates if no application messages are sent" is insufficient for high-threat environments. If a device is compromised, attackers can decrypt messages until the next epoch change.

**Solution:** Clients SHOULD piggyback a "Leaf Update" on application messages when the "Update Entropy" timer expires. The update frequency is configurable:

- **High Security Environments:** Every 10 messages OR 1 hour (whichever comes first)
- **Standard Environments:** Every 100 messages OR 24 hours
- **Low-Threat Environments:** Only when joining/leaving occurs

**Security Benefits:**

1. **Reduced Compromise Window:** Limits the time an attacker can decrypt messages after stealing keys
2. **Proactive Healing:** Doesn't require manual intervention or waiting for membership changes
3. **Gradual Key Rotation:** Spreads the computational cost of TreeKEM operations over time
4. **Forward Secrecy:** Ensures even silent participants eventually rotate keys

**Implementation Notes:**

- Passive updates (daily timer without messages) are INSUFFICIENT for high-threat scenarios
- Updates should be piggybacked on existing messages to avoid extra network overhead
- The timer resets whenever ANY epoch change occurs (not just self-initiated updates)
- In large groups (>1000 members), consider longer intervals to reduce TreeKEM overhead

```rust
impl MLSEngine {
    /// Create group
    pub fn create_group(
        &mut self,
        room_id: RoomId,
    ) -> Result<(MLSGroup, Welcome)> {
        // 1. Generate or Load Notification Keypair
        // CRITICAL: Private key must be stored in device secure storage
        // (iOS Keychain, Android Keystore) and NEVER transmitted.
        let notification_keypair = self.load_or_generate_notification_keypair()?;

        // 2. Define the PCEK Extension (PUBLIC KEY ONLY)
        let pcek_extension = Extension::new(
            0x000A, // Custom ID
            NotificationKeyExtension {
                public_key: notification_keypair.public_key
            }.encode()
        );

        // 3. Configure Group
        // NOTE: The MLS cipher suite must match the Sunder cipher suite chosen
        // For Suite 0x0003 (Performance), use X25519-based MLS suite
        // For Suite 0x0004 (FIPS), use P-384-based MLS suite
        let config = MlsGroupConfig::builder()
            .crypto_config(CryptoConfig::with_default_version(
                // This maps to Sunder Suite 0x0003 (Performance)
                CipherSuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            ))
            .use_ratchet_tree_extension(true)
            // INJECT EXTENSION HERE
            .with_leaf_extension(pcek_extension)
            .build();

        // 4. Initialize Group
        let group = MLSGroup::new(
            &self.provider,
            &self.credential.signing_key,
            config,
        )?;

        self.groups.insert(room_id, group.clone());

        Ok((group, Welcome::default()))
    }

    /// Load notification keypair from secure storage or generate new one
    fn load_or_generate_notification_keypair(&self) -> Result<NotificationKeypair> {
        // Try to load existing keypair from device secure storage
        if let Some(keypair) = self.keychain.load_notification_keypair()? {
            return Ok(keypair);
        }

        // Generate new keypair
        use x25519_dalek::{StaticSecret, PublicKey};
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);

        let keypair = NotificationKeypair {
            public_key: public.to_bytes(),
            private_key: private.to_bytes(),
        };

        // Store in device secure storage
        self.keychain.store_notification_keypair(&keypair)?;

        Ok(keypair)
    }
}
```

### 3.2 Sender Key Derivation

```rust
/// Bridge MLS epochs to sender keys
fn derive_sender_keys(
    epoch_secrets: &EpochSecrets,
) -> Result<HashMap<LeafIndex, SenderKey>> {
    let mut keys = HashMap::new();

    for leaf_index in 0..epoch_secrets.group_size() {
        let context = SenderKeyContext {
            epoch: epoch_secrets.epoch(),
            sender: leaf_index,
        };

        // Export from MLS (64 bytes: 32 for encryption + 32 for authentication)
        let key_material = epoch_secrets.export_secret(
            "SunderSenderV1",
            &context.encode(),
            64,
        )?;

        keys.insert(leaf_index, SenderKey {
            encryption_key: key_material[..32].try_into()?,
            authentication_key: key_material[32..64].try_into()?,
            generation: 0,
        });
    }

    Ok(keys)
}
```

---

## 4. Sync Engine

### 4.1 Dual-Loop Architecture

Control plane prioritized over data plane:

```rust
/// Sync coordinator
pub struct SyncEngine {
    /// Control plane (MLS commits)
    control_rx: mpsc::Receiver<ControlFrame>,

    /// Data plane (messages)
    data_rx: mpsc::Receiver<DataFrame>,

    /// Sync state per room
    rooms: HashMap<RoomId, RoomSync>,
}

struct RoomSync {
    epoch: u64,
    last_index: u64,
    pending_commits: VecDeque<MLSCommit>,
    message_buffer: VecDeque<MessageEnvelope>,
}

impl SyncEngine {
    pub async fn run(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                biased;  // Prioritize control

                // Process MLS commits first
                Some(control) = self.control_rx.recv() => {
                    self.process_control(control).await?;
                }

                // Then process messages
                Some(data) = self.data_rx.recv() => {
                    self.process_data(data).await?;
                }

                // Periodic tasks
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    self.heartbeat().await?;
                }
            }
        }
    }

    async fn process_control(&mut self, frame: ControlFrame) -> Result<()> {
        match frame.opcode {
            Opcode::Commit => {
                let room = self.rooms.get_mut(&frame.room_id)
                    .ok_or(Error::RoomNotFound)?;

                // Queue if out of order
                if frame.epoch != room.epoch + 1 {
                    room.pending_commits.push_back(frame.decode_commit()?);
                    room.pending_commits.sort_by_key(|c| c.epoch);
                    return Ok(());
                }

                // Process immediately
                self.apply_commit(frame.room_id, frame.decode_commit()?).await?;

                // Check for queued commits
                while let Some(commit) = room.pending_commits.front() {
                    if commit.epoch == room.epoch + 1 {
                        let commit = room.pending_commits.pop_front().unwrap();
                        self.apply_commit(frame.room_id, commit).await?;
                    } else {
                        break;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}
```

---

## 5. Mobile Optimization

### 5.1 iOS Architecture

#### Main App

```swift
/// Main app MLS processor
class MLSProcessor {
    let core: ClientCore
    let keyExporter: KeyExporter

    func processCommit(_ commit: Data) throws {
        // Heavy MLS operations
        let epochChange = try core.processCommit(commit)

        // Export keys for NSE
        let exportedKeys = ExportedKeys(
            epoch: epochChange.newEpoch,
            keys: epochChange.senderKeys.map { key in
                ExportedKey(
                    sender: key.sender,
                    keyData: key.encryption_key
                )
            }
        )

        // Write to shared container
        try keyExporter.export(exportedKeys)
    }
}

/// Shared key exporter
class KeyExporter {
    let sharedURL: URL

    func export(_ keys: ExportedKeys) throws {
        // Serialize to compact format
        let data = try BinaryEncoder.encode(keys)

        // Atomic write
        let tempURL = sharedURL.appendingPathComponent("keys.tmp")
        try data.write(to: tempURL)

        let finalURL = sharedURL.appendingPathComponent("keys.bin")
        _ = try FileManager.default.replaceItem(
            at: finalURL,
            withItemAt: tempURL,
            backupItemName: nil,
            options: .usingNewMetadataOnly
        )
    }
}
```

#### Notification Service Extension

````swift
```swift
/// NSE implementation using Push-Carried Ephemeral Keys (PCEK)
/// Prevents "Zombie Epoch" deadlocks by bypassing the MLS tree.
class NotificationService: UNNotificationServiceExtension {
    var contentHandler: ((UNNotificationContent) -> Void)?
    var bestAttemptContent: UNMutableNotificationContent?

    // Device-specific asymmetric keypair (Curve25519)
    // Private key stored in Keychain, NEVER transmitted
    let keyStore = KeychainStore()

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        self.contentHandler = contentHandler
        self.bestAttemptContent = (request.content.mutableCopy() as? UNMutableNotificationContent)

        guard let bestAttemptContent = bestAttemptContent else { return }

        // 1. Extract PCEK blob from APNS payload
        // Format: [ephemeral_public_key (32) | encrypted_message_key (48)]
        guard let pcekBlob = request.content.userInfo["pcek"] as? Data,
            let encryptedPayload = request.content.userInfo["payload"] as? Data else {
            // Not a PCEK message (maybe a generic alert), fail open
            contentHandler(bestAttemptContent)
            return
        }

        do {
            // 2. Load Device Private Key (from Keychain)
            let devicePrivateKey = try keyStore.loadNotificationPrivateKey()

            // 3. Decrypt the MessageKey using X25519 + ChaCha20-Poly1305
            // This does NOT require accessing the MLS tree or SQL database
            // Only this device can decrypt because only it has the private key
            let messageKey = try decryptPCEK(
                blob: pcekBlob,
                privateKey: devicePrivateKey
            )

            // 4. Decrypt the Payload (XChaCha20)
            let plaintext = try Crypto.decryptPayload(
                ciphertext: encryptedPayload,
                key: messageKey
            )

            // 5. Update Notification
            bestAttemptContent.body = String(data: plaintext, encoding: .utf8) ?? "Decryption Error"
            contentHandler(bestAttemptContent)
        } catch {
            // Fallback on error (e.g., "You have a new message")
            print("NSE Decryption failed: \(error)")
            contentHandler(bestAttemptContent)
        }
    }

    /// Decrypt PCEK blob with device private key
    private func decryptPCEK(blob: Data, privateKey: Data) throws -> Data {
        guard blob.count == 80 else {
            throw NSError(domain: "PCEK", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid PCEK blob size"])
        }

        // Extract ephemeral public key (first 32 bytes)
        let ephemeralPublicKey = blob[0..<32]

        // Perform X25519 ECDH
        let sharedSecret = try Crypto.x25519(
            privateKey: privateKey,
            publicKey: ephemeralPublicKey
        )

        // Derive decryption key
        let decryptionKey = try HKDF.deriveKey(
            inputKeyMaterial: sharedSecret,
            info: "PCEKv1".data(using: .utf8)!,
            outputByteCount: 32
        )

        // Decrypt ciphertext (last 48 bytes: 32 + 16 tag)
        let ciphertext = blob[32..<80]
        let messageKey = try ChaCha20Poly1305.decrypt(
            ciphertext: ciphertext,
            key: decryptionKey,
            nonce: Data(count: 12) // Zero nonce (safe with ephemeral key)
        )

        return messageKey
    }

    override func serviceExtensionTimeWillExpire() {
        // Called if decryption takes too long (>30s)
        if let contentHandler = contentHandler,
           let bestAttemptContent = bestAttemptContent {
           contentHandler(bestAttemptContent)
        }
    }
}
```

### 5.2 Android Architecture

```kotlin
/// Foreground service for reliable sync
class SyncService : Service() {
    private val core = ClientCore()
    private lateinit var wakeLock: PowerManager.WakeLock

    override fun onCreate() {
        super.onCreate()

        // Acquire partial wake lock
        val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = powerManager.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "Client::SyncWakeLock"
        )

        // Start foreground
        val notification = createNotification()
        startForeground(NOTIFICATION_ID, notification)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        wakeLock.acquire(5 * 60 * 1000L) // 5 minutes

        lifecycleScope.launch {
            try {
                // Process in priority order
                processControlPlane()
                processDataPlane()
            } finally {
                if (wakeLock.isHeld) {
                    wakeLock.release()
                }
            }
        }

        return START_STICKY
    }

    private suspend fun processControlPlane() {
        core.syncCommits()
    }

    private suspend fun processDataPlane() {
        core.syncMessages()
    }
}
````

---

## 6. Network Layer

### 6.1 QUIC Client

```rust
/// QUIC connection manager
pub struct ConnectionManager {
    endpoint: quinn::Endpoint,
    connection: Option<quinn::Connection>,
    config: ClientConfig,
    reconnect_timer: Option<Timer>,
}

impl ConnectionManager {
    pub async fn connect(&mut self) -> Result<()> {
        let config = quinn::ClientConfig::new(Arc::new(
            rustls::ClientConfig::builder()
                .with_cipher_suites(&[
                    rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
                    rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                ])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth()
                .enable_early_data()  // 0-RTT
                .build()?,
        ));

        let connection = self.endpoint
            .connect(self.config.server_addr, self.config.server_name)?
            .await?;

        self.connection = Some(connection);
        Ok(())
    }

    pub async fn send_frame(&mut self, frame: Frame) -> Result<()> {
        let connection = self.connection.as_mut()
            .ok_or(Error::NotConnected)?;

        // Open bidirectional stream
        let (mut send, recv) = connection.open_bi().await?;

        // Send frame
        frame.write_to(&mut send).await?;
        send.finish().await?;

        // Wait for response (read header then payload)
        let mut header_bytes = [0u8; FrameHeader::SIZE];
        recv.read_exact(&mut header_bytes).await?;
        let header = FrameHeader::from_bytes(&header_bytes)?;

        let payload_size = u32::from_be(header.payload_size) as usize;
        let mut payload = vec![0u8; payload_size];
        recv.read_exact(&mut payload).await?;

        let response = Frame { header: *header, payload };

        match response.opcode {
            Opcode::Error => Err(Error::Server(response.decode_error()?)),
            _ => Ok(()),
        }
    }

    /// Send message with automatic epoch recovery (Zombie Epoch Protection)
    ///
    /// CRITICAL: On mobile networks, clients frequently go offline during epoch
    /// transitions (when members join/leave). Without automatic recovery, users
    /// see "Message Failed" errors and must manually retry, causing poor UX.
    ///
    /// This wrapper transparently catches up to the current epoch when the server
    /// rejects a message with Error::StaleEpoch, then retries the send.
    pub async fn send_message_with_recovery(
        &mut self,
        room_id: RoomId,
        content: &[u8],
    ) -> Result<()> {
        const MAX_RECOVERY_ATTEMPTS: u8 = 3;
        let mut attempts = 0;

        loop {
            match self.send_message_internal(room_id, content).await {
                Ok(_) => return Ok(()),

                Err(Error::StaleEpoch { current_epoch, expected_epoch }) => {
                    attempts += 1;

                    if attempts >= MAX_RECOVERY_ATTEMPTS {
                        return Err(Error::EpochRecoveryFailed {
                            attempts,
                            stuck_at: current_epoch,
                        });
                    }

                    tracing::warn!(
                        "Stale epoch detected (client: {}, server: {}), recovering...",
                        current_epoch,
                        expected_epoch
                    );

                    // Transparently sync to current epoch
                    self.sync_to_epoch(room_id, expected_epoch).await?;

                    // Re-encrypt message for new epoch and retry
                    // User doesn't see any error
                    continue;
                }

                // Other errors bubble up immediately
                Err(e) => return Err(e),
            }
        }
    }

    /// Sync client to a specific epoch by fetching missing commits
    async fn sync_to_epoch(&mut self, room_id: RoomId, target_epoch: u64) -> Result<()> {
        let room = self.get_room_mut(room_id)?;

        // Fetch commits from current epoch to target epoch
        while room.epoch < target_epoch {
            let next_commit = self.fetch_commit(room_id, room.epoch + 1).await?;
            room.process_commit(next_commit)?;
        }

        Ok(())
    }
}
```

### 6.2 Reconnection Strategy

```rust
/// Exponential backoff with jitter
struct ReconnectStrategy {
    attempt: u32,
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl ReconnectStrategy {
    fn next_delay(&mut self) -> Option<Duration> {
        if self.attempt >= self.max_attempts {
            return None;
        }

        self.attempt += 1;

        // Exponential backoff with jitter
        let exponential = self.base_delay * 2u32.pow(self.attempt - 1);
        let clamped = exponential.min(self.max_delay);

        // Add jitter (±25%)
        let jitter = rand::random::<f64>() * 0.5 - 0.25;
        let with_jitter = clamped.mul_f64(1.0 + jitter);

        Some(with_jitter)
    }

    fn reset(&mut self) {
        self.attempt = 0;
    }
}
```

---

## 7. Performance Optimizations

### 7.1 Message Batching

```rust
/// Batch outgoing messages
struct MessageBatcher {
    pending: Vec<Frame>,
    max_batch: usize,
    flush_interval: Duration,
    last_flush: Instant,
}

impl MessageBatcher {
    async fn add(&mut self, frame: Frame) -> Result<()> {
        self.pending.push(frame);

        if self.should_flush() {
            self.flush().await?;
        }

        Ok(())
    }

    fn should_flush(&self) -> bool {
        self.pending.len() >= self.max_batch ||
        self.last_flush.elapsed() >= self.flush_interval
    }

    async fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }

        // Send as single QUIC datagram
        let batch = std::mem::take(&mut self.pending);
        send_batch(batch).await?;

        self.last_flush = Instant::now();
        Ok(())
    }
}
```

### 7.2 Crypto Optimization

```rust
/// Hardware-accelerated crypto where available
#[cfg(target_arch = "x86_64")]
fn setup_crypto() {
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
        // Use AES-NI
        crypto::set_provider(crypto::Provider::Hardware);
    }
}

#[cfg(target_arch = "aarch64")]
fn setup_crypto() {
    if std::arch::is_aarch64_feature_detected!("aes") {
        // Use ARM crypto extensions
        crypto::set_provider(crypto::Provider::Hardware);
    }
}
```

---

## 8. Platform Bindings

### 8.1 UniFFI Interface

```rust
// client.udl

namespace client {
    [Throws=ClientError]
    ClientClient create_client(string database_path);
};

interface ClientClient {
    [Throws=ClientError]
    void connect(string server_url);

    [Throws=ClientError]
    Room create_room(string room_id);

    [Throws=ClientError]
    Room join_room(string room_id, bytes welcome);

    [Throws=ClientError]
    void send_message(string room_id, string content);

    sequence<Message> get_messages(string room_id, i64 limit);
};

dictionary Room {
    string room_id;
    u64 epoch;
    sequence<Member> members;
};

dictionary Message {
    u64 log_index;
    u32 sender_index;
    string content;
    i64 timestamp;
};

[Error]
enum ClientError {
    "NetworkError",
    "CryptoError",
    "DatabaseError",
    "InvalidState",
};
```

### 8.2 Build Configuration

```toml
# Cargo.toml

[package]
name = "client-core"
version = "4.0.0"

[lib]
crate-type = ["cdylib", "staticlib", "rlib"]

[dependencies]
# Core
tokio = { version = "1.38", features = ["full"] }
quinn = "0.11"
rustls = "0.23"

# MLS
openmls = { version = "1.0", features = ["crypto-subtle"] }
openmls_rust_crypto = "0.3"

# Database
rusqlite = { version = "0.32", features = ["bundled-sqlcipher"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
bincode = "1.3"

# Platform
uniffi = "0.28"

[target.'cfg(target_os = "ios")'.dependencies]
swift-bridge = "0.1"

[target.'cfg(target_os = "android")'.dependencies]
jni = "0.21"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

---

## 9. Testing Strategy

### 9.1 Deterministic Testing

```rust
#[cfg(test)]
mod tests {
    use turmoil;

    #[test]
    fn test_epoch_synchronization() {
        let mut sim = turmoil::Builder::new()
            .simulation_duration(Duration::from_secs(60))
            .build();

        // Create 3 clients
        for i in 0..3 {
            sim.client(format!("client-{}", i), async move {
                let client = ClientClient::new();
                client.connect("server").await.unwrap();
                client.join_room("test-room").await.unwrap();
            });
        }

        // Simulate network partition
        sim.partition("client-1", "server");

        // Client 2 sends commit
        sim.client("client-2", async {
            client.send_commit().await.unwrap();
        });

        // Heal partition
        sim.heal_all();

        // Verify all clients converge
        for i in 0..3 {
            let epoch = sim.client(format!("client-{}", i), async {
                client.get_epoch().await
            });
            assert_eq!(epoch, 2);
        }
    }
}
```

---

## References

1. UniFFI Documentation: https://mozilla.github.io/uniffi-rs/
2. SQLCipher: https://www.zetetic.net/sqlcipher/
3. OpenMLS: https://openmls.tech/
4. iOS App Extensions: https://developer.apple.com/documentation/usernotifications/
5. Android Foreground Services: https://developer.android.com/develop/background-work/services/foreground-services
