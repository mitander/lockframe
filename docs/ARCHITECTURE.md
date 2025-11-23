# Sunder Architecture Document

## Executive Summary

Sunder is a sovereign messaging protocol that combines cryptographic rigor with operational pragmatism. Unlike Matrix's eventual consistency model or Signal's client-heavy architecture, Sunder employs a "hub-centric design" where servers actively participate in group management through MLS External Commits while maintaining end-to-end encryption guarantees.

The architecture prioritizes:

- **Deterministic behavior** over probabilistic guarantees
- **Server sovereignty** over pure decentralization
- **Cryptographic enforcement** over policy-based security
- **Forensic compliance** over deniability

---

## 1. Core Design Philosophy

### 1.1 The Sovereign Hub Model

Traditional E2EE messaging treats servers as passive relays. This creates operational blindspots:

- Malicious clients can DoS groups through proposal spam
- Banned users retain cryptographic material indefinitely
- Content moderation requires client cooperation
- Federation lacks authoritative ordering

Solution: Servers are first-class MLS participants through the External Senders extension (RFC 9420 §12.1). This enables:

```
Traditional:  Client → Server (relay) → Client
Sunder:       Client ↔ Server (participant) ↔ Client
```

The server can:

- Generate MLS Commits to remove bad actors (cryptographic ban)
- Enforce linear ordering (sequencer pattern)
- Implement retention policies (secure deletion)
- Bridge federation domains (double-signed transactions)

### 1.2 The Dual-Plane Architecture

MLS provides strong security but has performance limitations for high-frequency messaging. TreeKEM operations scale O(log n) but still require significant computation.

The solution is to separate concerns:

**Control Plane (MLS):**

- Membership changes (add/remove)
- Key agreement (TreeKEM)
- Epoch advancement
- Authentication

**Data Plane (Sender Keys):**

- Message encryption (XChaCha20-Poly1305)
- Forward secrecy (symmetric ratchet)
- Low latency (<5ms crypto overhead)
- Parallel processing

The planes are cryptographically bound:

```
SenderKeySeed = MLS.Export("SunderSenderKeyV1", context, 32)
```

This provides:

- **~100x throughput** vs pure MLS (theoretically)
- **Forward secrecy** per message
- **Post-compromise security** per epoch
- **Constant-time** encryption/decryption

### 1.3 Deterministic Simulation Testing

To ensure correctness, every component is testable in deterministic simulation:

```rust
// Example from our test harness
#[test]
fn test_split_brain_recovery() {
    let mut sim = turmoil::Builder::new()
        .simulation_duration(Duration::from_secs(60))
        .build();

    // Partition network at t=10s
    sim.partition("hub1", "hub2");

    // Both hubs receive commits
    sim.client("alice").send_commit();
    sim.client("bob").send_commit();

    // Heal partition at t=30s
    sim.heal_all();

    // Verify convergence
    assert_eq!(
        sim.hub("hub1").tree_hash(),
        sim.hub("hub2").tree_hash()
    );
}
```

Every race condition, network partition, and edge case should be reproducible.

---

## 2. Technical Architecture

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────┐
│                       Client                        │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │   UI Layer  │  │ Sync Engine │  │  MLS Core   │  │
│  │  (SwiftUI/  │←→│   (Rust)    │←→│   (Rust)    │  │
│  │   Compose)  │  │             │  │             │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  │
│                          ↓                          │
│                   ┌─────────────┐                   │
│                   │   SQLite    │                   │
│                   │ (Encrypted) │                   │
│                   └─────────────┘                   │
└─────────────────────────────────────────────────────┘
                          ↓ QUIC
┌─────────────────────────────────────────────────────┐
│                       Server                        │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │   Gateway   │→ │  Sequencer  │→ │   Storage   │  │
│  │   (QUIC)    │  │  (Per Room) │  │   (Redb)    │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  │
│         ↓                ↓                ↓         │
│  ┌───────────────────────────────────────────────┐  │
│  │            MLS State Machine (Shared)         │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### 2.2 Storage Architecture

#### Server Storage (Hybrid Strategy)

**State Store (Redb):** Stores persistent, non-sensitive structure (MLS Tree, Member Lists, Headers). Uses Copy-on-Write for crash safety.

Redb provides ACID guarantees with deterministic page management:

```rust
// Multi-table atomic transactions
let txn = db.begin_write()?;
{
    // Update log and MLS state atomically
    txn.open_table(TABLE_LOG)?.insert((room_id, index), frame)?;
    txn.open_table(TABLE_MLS_STATE)?.insert(room_id, new_state)?;
}
txn.commit()?; // All or nothing
```

Why Redb over alternatives:

- **RocksDB:** Non-deterministic compaction, forensic leakage
- **LMDB:** No secure deletion, fixed map size
- **SQLite:** Row-oriented inefficient for log storage
- **Sled:** Abandoned, unstable format

**KeyStore (Volatile/Linear):** Stores PayloadKeys and SenderKeys.

Implementation: Memory-mapped file with fixed-size slots or RAM-only storage.

Critical: This store MUST support in-place overwriting (not Copy-on-Write) to attempt physical destruction of key material.

#### Client Storage (SQLite + SQLCipher)

SQLite for relational queries, SQLCipher for encryption at rest:

```sql
PRAGMA cipher_page_size = 4096;
PRAGMA kdf_iter = 256000;
PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
PRAGMA crypto_delete = ON;  -- Critical for forensics
```

### 2.3 Networking Architecture

#### QUIC Transport

QUIC provides critical features for mobile messaging:

**Connection Migration:**

- Survives network switches (WiFi → Cellular)
- Connection ID persists across IP changes
- Zero round-trip resumption (0-RTT)

**Stream Multiplexing:**

- Control plane on Stream 0 (prioritized)
- Data plane on Streams 1-N (parallel)
- Per-stream flow control

**Performance Metrics (theoretical):**

- 25-30% latency reduction vs TCP+TLS
- 50% reduction in handshake overhead
- 3x faster recovery from packet loss

```rust
// QUIC configuration
let config = quinn::ServerConfig::builder()
    .with_crypto(rustls_config)
    .max_idle_timeout(Some(Duration::from_secs(30)))
    .keep_alive_interval(Some(Duration::from_secs(10)))
    .migration(true)  // Enable connection migration
    .build();
```

---

## 3. Security Architecture

### 3.1 Threat Model

**Adversaries:**

- **Network attackers:** Can observe, drop, reorder packets
- **Malicious clients:** Can send invalid proposals, spam messages
- **Compromised servers:** Cannot decrypt past/future messages
- **Regulatory actors:** Require content removal, user bans

**Non-goals:**

- Metadata privacy (use Tor/mixnets if needed)
- Traffic analysis resistance
- Deniability (explicitly not supported for compliance)

### 3.2 Cryptographic Design

#### Key Hierarchy

```
                    IdentityKey (ML-DSA-65)
                           │
                    ┌──────┴──────┐
                    │             │
              SigningKey   InitKey (ML-KEM-768)
              (Ed25519)           │
                    │             │
            ┌───────┴──────┐      │
            │              │      │
      PreKeyBundle    EpochSecret │
            │            (MLS)    │
            │              │      │
            │         SenderKeys  │
            │              │      │
            └──────────────┴──────┘
                           │
                      MessageKeys
```

#### Cipher Suite Agility

To satisfy both performance and compliance requirements, the protocol supports two mandatory suites:

1. **Suite 0x0003 (Performance - Default):** X25519 + ML-KEM-768 + XChaCha20-Poly1305 + Ed25519
2. **Suite 0x0004 (Compliance/FIPS):** P-384 + ML-KEM-768 + AES-256-GCM + ECDSA-P384

| Component     | Suite 0x0003 (Performance) | Suite 0x0004 (FIPS) | Purpose            |
| ------------- | -------------------------- | ------------------- | ------------------ |
| **KEM**       | X25519 + ML-KEM-768        | P-384 + ML-KEM-768  | Key encapsulation  |
| **AEAD**      | XChaCha20-Poly1305         | AES-256-GCM         | Message encryption |
| **KDF**       | HKDF-SHA256                | HKDF-SHA384         | Key derivation     |
| **Signature** | Ed25519                    | ECDSA-P384          | Authentication     |

#### Post-Quantum Readiness (Hybrid KEM)

The hybrid approach provides quantum resistance while maintaining classical security:

```rust
// Hybrid KEM Combination (both suites)
let shared_secret = kdf_extract(
    concat(
        ecdh_secret(priv, pub),  // Classical (32 bytes for X25519, 48 for P-384)
        pq_secret(priv, pub)     // Post-Quantum ML-KEM-768 (32 bytes)
    )
);
```

This ensures security even if either the classical or post-quantum algorithm is compromised. Current hybrid approach adds ~1KB per handshake.

### 3.3 Authentication Architecture

#### Privacy Pass Integration

Rate limiting without tracking:

```
Client                      Server
  │                           │
  ├──────── BlindToken ──────→│
  │                           │ (Verify proof-of-work)
  │←─────── SignedToken ──────┤
  │                           │
  ├─────── Redeem(Token) ────→│
  │                           │ (Grant access)
```

This provides:

- Anonymous rate limiting
- DDoS protection
- No user tracking

---

## 4. Operational Architecture

### 4.1 Moderation Capabilities

#### Cryptographic Enforcement

Traditional moderation relies on policy (IP bans, account suspension). Sunder uses cryptography:

```rust
// Server-initiated removal
fn execute_ban(room_id: RoomId, target: LeafIndex) {
    // Generate External Commit removing target
    let commit = mls.create_external_commit(
        RemoveProposal::new(target),
        server_credential
    );

    // New epoch excludes target from key derivation
    broadcast(commit);

    // Target cannot derive new epoch secret
    // Mathematical guarantee, not policy
}
```

#### Forensic Compliance via Cryptographic Erasure

Physical overwriting (zeroing) is ineffective on modern SSDs due to wear leveling. Compliance can instead be achieved with **Cryptographic Erasure**:

1. **Per-Message Keys:** Every message payload is encrypted with a unique, ephemeral 256-bit `PayloadKey`.
2. **Key Storage:** The `PayloadKey` is stored in a separate table from the ciphertext.
3. **Erasure:** To "delete" a message, we destroy the `PayloadKey`.
4. **Guarantee:** Without the key, the ciphertext remains on the physical disk as statistically random noise, regardless of SSD garbage collection.

### 4.2 Federation Architecture

#### Double-Signed Protocol

Prevents both server spoofing and client impersonation:

```
Layer 1: Transport Security
┌─────────────────────────────────┐
│ QUIC Connection (TLS 1.3)       │
│ Authenticates: hub1.example.com │
└─────────────────────────────────┘

Layer 2: Federation Signature
┌─────────────────────────────────┐
│ Hub Signature (Ed25519)         │
│ Signs: Frame + Timestamp        │
└─────────────────────────────────┘

Layer 3: User Signature
┌─────────────────────────────────┐
│ MLS Signature (from Tree)       │
│ Signs: Message Content          │
└─────────────────────────────────┘
```

#### Authoritative Home Server

To prevent split-brain scenarios without complex consensus:

- Each room has exactly one **Home Server** (defined by the RoomID).
- The Home Server is the sole Sequencer.
- Federation logic is **Hub-and-Spoke**, not Mesh.
- Authority transfer is a "Stop-the-World" migration event, not a dynamic vote.

---

## 5. Performance Architecture

### 5.1 Scalability Targets

Based on real-world messaging patterns:

| Metric            | Target           | Method          |
| ----------------- | ---------------- | --------------- |
| Group Size        | 10,000 members   | Test cluster    |
| Message Rate      | 10K msg/sec/room | Load generator  |
| Encryption        | <5ms             | XChaCha20 bench |
| Commit Processing | <100ms           | MLS bench       |
| Storage/Message   | <1KB             | Compressed      |
| Federation Lag    | <50ms            | Cross-region    |

### 5.2 Optimization Strategies

#### Sharded Sequencer

Room assignment via consistent hashing:

```rust
// Each core handles ~1000 rooms
// No lock contention between cores
fn assign_sequencer(room_id: RoomId) -> CoreId {
    // Deterministic assignment
    let hash = xxh3_64(room_id.as_bytes());
    (hash % num_cores) as CoreId
}
```

#### Zero-Copy Message Path

```rust
// BAD: Multiple allocations
let msg = decrypt(bytes.to_vec());
let parsed = parse(msg.clone());
send(parsed.to_vec());

// GOOD: Single allocation
let msg = decrypt_in_place(&mut bytes);
let parsed = parse_ref(&msg);
send_ref(&parsed);
```

#### Memory-Mapped Logs

Redb uses mmap for zero-copy reads:

```rust
// Pages mapped directly to memory
let page = unsafe {
    MmapOptions::new()
        .len(PAGE_SIZE)
        .offset(page_offset)
        .map(&file)?
};

// No syscall for reads
let data = &page[offset..offset + len];
```

---

## 6. Mobile Architecture

### 6.1 iOS Constraints

The Notification Service Extension has severe limitations:

| Resource | Limit      | Impact                 |
| -------- | ---------- | ---------------------- |
| Memory   | 24MB       | Cannot load MLS tree   |
| CPU Time | 30 seconds | Cannot process commits |
| Disk I/O | Limited    | Cannot access main DB  |

### 6.2 Mobile Push Strategy (PCEK)

The NSE cannot process MLS Commits due to memory limits. We solve this via **Push-Carried Ephemeral Keys (PCEK)** for high-priority messages (DMs, mentions).

**The Protocol:**

1. **Device generates asymmetric keypair:** Each device generates a Curve25519 keypair on first launch. The **private key never leaves the device** (stored in iOS Keychain / Android Keystore).

2. **Public key published in KeyPackage:** The device publishes the **public key** in its MLS KeyPackage via the NotificationKeyExtension (ID: 0x000A).

3. **Sender encrypts MessageKey:** When sending a message, the sender:
   - Generates the `MessageKey` (from the MLS ratchet)
   - **Encrypts this MessageKey** using the recipient's **public NotificationKey** (X25519 + ChaCha20-Poly1305)
   - Produces an 80-byte blob: `[ephemeral_public_key (32) | encrypted_message_key (48)]`

4. **Push notification delivery:** The server forwards the PCEK blob to APNS/FCM, which delivers it to the NSE.

5. **NSE Decryption:**
   - Load device **private key** from Keychain
   - Decrypt the PCEK blob using X25519 ECDH + ChaCha20-Poly1305
   - Decrypt the message content with the recovered MessageKey
   - **Note:** This bypasses the MLS tree for the _notification only_, preventing the "Zombie Epoch" deadlock while maintaining confidentiality.

**Security Benefits:**

- ✅ **Battery Drain Prevention:** Only the target device can decrypt its notification. Malicious group members cannot spam notifications to other members because they don't have the private keys.
- ✅ **Server Rate Limiting:** The server can rate-limit push notifications by sender without breaking encryption.
- ✅ **No Key Sharing:** Private keys never leave the device or enter the MLS key schedule.

**Trade-offs:**

- **Overhead:** +80 bytes per push notification
- **Computation:** One X25519 scalar multiplication per notification (~50μs on modern devices)

### 6.3 Android Architecture

Foreground Service for reliability:

```kotlin
class SyncService : ForegroundService() {
    override fun onStartCommand(intent: Intent): Int {
        // Partial wake lock
        wakeLock.acquire(TimeUnit.MINUTES.toMillis(5))

        // Process in priority order
        processControlPlane()  // MLS commits first
        processDataPlane()     // Messages second

        return START_STICKY
    }
}
```

---

## 7. Production Readiness

### 7.1 Observability

Structured metrics following RED method:

```rust
// Rate
counter!("messages.sent", 1, "room" => room_id);

// Errors
counter!("commits.failed", 1, "reason" => "stale_epoch");

// Duration
histogram!("encryption.duration", start.elapsed());
```

### 7.2 Deployment Strategy

Blue-green deployment with version negotiation:

```rust
// Protocol version in frame header (single byte)
const PROTOCOL_VERSION: u8 = 0x01; // Version 1

// Application version for feature negotiation (semantic versioning)
const APP_VERSION: u32 = 0x00010000; // 1.0.0

fn negotiate_version(client_version: u8) -> Result<u8> {
    match client_version {
        0x01 => Ok(0x01), // Current version
        _ => Err(Error::UnsupportedVersion(client_version))
    }
}
```

### 7.3 Disaster Recovery

All state is reconstructible from the log:

```rust
fn rebuild_state(log: &[Frame]) -> MLSState {
    let mut state = MLSState::new();

    for frame in log {
        match frame.opcode {
            Opcode::MLSCommit => state.apply_commit(frame),
            Opcode::MLSWelcome => state.add_member(frame),
            _ => continue,
        }
    }

    state
}
```

---

## 8. Comparison with Alternatives

| Feature               | Sunder                 | Matrix         | Signal          | WhatsApp        |
| --------------------- | ---------------------- | -------------- | --------------- | --------------- |
| Protocol              | MLS (RFC 9420)         | Megolm         | Signal Protocol | Signal Protocol |
| Group Size            | 10,000+                | 1,000          | 1,000           | 1,024           |
| Server Authority      | Yes (External Commits) | No             | No              | Unknown         |
| Federation            | Yes (Double-signed)    | Yes (Eventual) | No              | No              |
| Forensic Compliance   | Yes (Crypto delete)    | Partial        | No              | Unknown         |
| Post-Quantum          | Ready (ML-KEM)         | No             | PQXDH           | Unknown         |
| Deterministic Testing | Yes                    | No             | Unknown         | Unknown         |
| Open Source           | Yes                    | Yes            | Partial         | No              |

---

## 9. Future Directions

### 9.1 Post-Quantum Migration

PQC deployment:

- Hybrid mode (X25519 + ML-KEM)
- Performance optimization
- Full PQC mode

### 9.2 Decentralized Identity

Integration with DID/Verifiable Credentials:

- Self-sovereign identity
- Cross-platform portability
- Regulatory compliance

### 9.3 Hardware Security Modules

TPM/Secure Enclave integration:

- Key storage in hardware
- Remote attestation
- Side-channel resistance

---

## References

1. RFC 9420: The Messaging Layer Security (MLS) Protocol
2. RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
3. RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
4. RFC 9578: Privacy Pass Protocol
5. NIST FIPS 203: ML-KEM Standard
6. NIST FIPS 204: ML-DSA Standard
7. Redb Design Document: https://github.com/cberner/redb/blob/master/docs/design.md
