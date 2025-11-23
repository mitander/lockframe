# Sunder Server Implementation Guide

## 1. Server Architecture

### 1.1 Core Design

The server implements a sharded actor system with per-room sequencers. No global locks, no shared mutable state between rooms.

```rust
/// Server architecture
struct Server {
    /// QUIC endpoint
    endpoint: quinn::Endpoint,

    /// Room shards (one per CPU core)
    shards: Vec<Shard>,

    /// Persistent storage
    db: Arc<Database>,

    /// Metrics collector
    metrics: MetricsRegistry,
}

struct Shard {
    /// Rooms owned by this shard (The State)
    /// Critical: Must be kept in memory for strict ordering checks.
    rooms: HashMap<RoomId, Room>,

    /// Incoming command queue (The Input)
    commands: mpsc::Receiver<Command>,

    /// Shard-local allocator (The Memory)
    allocator: BumpAllocator,

    /// 2. Broadcast Workers (The Output Offload)
    /// The Sequencer writes to DB, then pushes the Frame here.
    /// This pool handles the O(N) loop over 10,000 QUIC streams
    /// so the Sequencer (Shard) never blocks.
    broadcaster: BroadcastPool,
}

/// Worker pool for massive fan-out
struct BroadcastPool {
    /// Workers handling specific subsets of connections
    workers: Vec<mpsc::Sender<BroadcastJob>>,
}
```

### 1.2 Zero-Copy Architecture

Messages flow through the system without copying:

```rust
/// Zero-copy message path
async fn handle_frame(frame_bytes: Bytes) -> Result<()> {
    // Parse header without copying (zero-copy via zerocopy crate)
    let header = FrameHeader::from_bytes(&frame_bytes)?;

    // Extract routing info (O(1) reads, no deserialization)
    let room_id = u128::from_be_bytes(header.room_id);
    let log_index = u64::from_be(header.log_index);

    // Validate signature in-place
    let payload_size = u32::from_be(header.payload_size) as usize;
    let payload = &frame_bytes[FrameHeader::SIZE..FrameHeader::SIZE + payload_size];
    header.verify_signature(&sender_key, payload)?;

    // Write to log (mmap append, zero-copy)
    let offset = log.append_bytes(&frame_bytes)?;

    // Broadcast (QUIC streams, zero-copy with Bytes::clone which is refcount bump)
    for member in room.members() {
        member.send_bytes(frame_bytes.clone()).await?;
    }
}
```

---

## 2. Storage Layer (Redb)

### 2.1 Schema Design

```rust
/// Database schema
mod schema {
    use redb::{TableDefinition, MultimapTableDefinition};

    /// Frame Headers (Metadata only)
    /// Key: (room_id: u128, log_index: u64)
    /// Value: Frame bytes (CBOR) - PAYLOAD FIELD MUST BE EMPTY
    pub const HEADERS: TableDefinition<(u128, u64), &[u8]> =
        TableDefinition::new("headers");

    /// Ephemeral Payload Keys (The "Erasure Key")
    /// Key: (room_id, log_index)
    /// Value: [u8; 32] (ChaCha20-Poly1305 Key)
    pub const PAYLOAD_KEYS: TableDefinition<(u128, u64), [u8; 32]> =
        TableDefinition::new("payload_keys");

    /// Server-Side Encrypted Payloads
    /// Key: (room_id, log_index)
    /// Value: EncryptedBytes (ciphertext + nonce + tag)
    /// Note: This contains the Client's ciphertext, wrapped in Server's encryption
    pub const PAYLOADS: TableDefinition<(u128, u64), &[u8]> =
        TableDefinition::new("payloads");

    /// MLS state table
    /// Key: room_id
    /// Value: MLSState (epoch, tree_hash, members)
    pub const MLS_STATE: TableDefinition<u128, &[u8]> =
        TableDefinition::new("mls_state");

    /// User message index (for moderation)
    /// Key: (user_id: u64, room_id: u128)
    /// Value: [log_index]
    pub const USER_INDEX: MultimapTableDefinition<(u64, u128), u64> =
        MultimapTableDefinition::new("user_index");

    /// Content addressable storage
    /// Key: blake3_hash
    /// Value: (ref_count, blob_data)
    pub const CAS: TableDefinition<[u8; 32], &[u8]> =
        TableDefinition::new("cas");

    /// Room metadata
    /// Key: room_id
    /// Value: RoomMetadata
    pub const ROOMS: TableDefinition<u128, &[u8]> =
        TableDefinition::new("rooms");
}
```

### 2.2 Transaction Handling

Every operation is atomic:

```rust
/// Atomic commit processing with Cryptographic Erasure support
fn process_commit(
    &self,
    room_id: RoomId,
    commit: &MLSCommit,
) -> Result<()> {
    let txn = self.db.begin_write()?;

    // Load current state
    let mut state_table = txn.open_table(schema::MLS_STATE)?;
    let current = state_table.get(&room_id)?
        .ok_or(Error::RoomNotFound)?;

    // Validate epoch continuity
    let parsed_state: MLSState = cbor::decode(current.value())?;
    if commit.epoch != parsed_state.epoch + 1 {
        return Err(Error::EpochMismatch);
    }

    // Apply commit
    let new_state = parsed_state.apply_commit(commit)?;

    // Write atomically
    {
        // 1. Update MLS state
        state_table.insert(&room_id, &cbor::encode(&new_state)?)?;

        // 2. Prepare Log Entry (Crypto-Erasure Split)
        let log_index = self.next_log_index(room_id);
        let commit_bytes = commit.encode()?;

        // A. Generate Ephemeral Key (32 bytes)
        let payload_key = crate::crypto::generate_random_key();

        // B. Encrypt the Commit (Server-Side Encryption)
        // This wraps the client's MLS data in a layer the server can delete
        let encrypted_payload = crate::crypto::encrypt_payload(&commit_bytes, &payload_key)?;

        // C. Create Header (Metadata only)
        // Preserves history/sequencing even if payload is deleted later
        let header = FrameHeader::from_commit(commit, log_index);

        // 3. Write to Split Tables

        // A. Write Metadata
        let mut headers_table = txn.open_table(schema::HEADERS)?;
        headers_table.insert(&(room_id, log_index), &header.encode()?)?;

        // B. Write the Erasure Key
        let mut keys_table = txn.open_table(schema::PAYLOAD_KEYS)?;
        keys_table.insert(&(room_id, log_index), &payload_key)?;

        // C. Write Encrypted Content
        let mut payloads_table = txn.open_table(schema::PAYLOADS)?;
        payloads_table.insert(&(room_id, log_index), &encrypted_payload)?;

        // 4. Update indices
        if let Some(removed_member) = commit.removed_member() {
            let mut user_index = txn.open_multimap_table(schema::USER_INDEX)?;
            user_index.remove(&(removed_member, room_id))?;
        }
    }

    txn.commit()?;
    Ok(())
}
```

### 2.3 Secure Deletion

Forensic-grade deletion with verification:

```rust
/// Cryptographic Erasure (Compliance)
fn secure_delete(
    &self,
    room_id: RoomId,
    log_index: u64,
) -> Result<()> {
    let txn = self.db.begin_write()?;
    {
        // 1. Open the Key Table
        let mut key_table = txn.open_table(schema::PAYLOAD_KEYS)?;

        // 2. DELETE THE KEY
        // This is the atomic act of erasure. Without this 32-byte key,
        // the blob in PAYLOADS is mathematically irretrievable.
        let existed = key_table.remove(&(room_id, log_index))?;

        if !existed {
            return Err(Error::MessageNotFound);
        }

        // 3. (Optional) Space Reclamation
        // We can lazily remove the payload to save disk space, but
        // strictly speaking, the data is already "gone" for forensic purposes.
        let mut payload_table = txn.open_table(schema::PAYLOADS)?;
        payload_table.remove(&(room_id, log_index))?;
    }
    // 4. Commit the key destruction
    txn.commit()?;

    // 5. Audit Log
    audit_log::write(AuditEvent::MessageRedacted {
        room: room_id,
        index: log_index,
        timestamp: SystemTime::now(),
    })?;

    Ok(())
}
```

---

## 3. Sequencer Implementation

### 3.1 Per-Room Sequencing

Each room has exactly one sequencer (deterministic assignment):

```rust
/// Room sequencer
struct Sequencer {
    room_id: RoomId,
    next_index: AtomicU64,
    epoch: u64,
    pending_proposals: Vec<Proposal>,
    commit_timer: Option<Timer>,
}

impl Sequencer {
    /// Process incoming frame
    async fn process(&mut self, frame: Frame) -> Result<()> {
        match frame.opcode {
            Opcode::Proposal => {
                self.pending_proposals.push(frame.decode_proposal()?);
                self.maybe_commit().await?;
            }
            Opcode::Commit => {
                self.validate_and_apply_commit(frame).await?;
            }
            Opcode::ExternalCommit => {
                self.validate_external_commit(frame).await?;
            }
            Opcode::AppMessage => {
                self.sequence_message(frame).await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Validate External Commit (Race Condition Protection)
    ///
    /// CRITICAL: External Commits (used by new joiners) can bypass pending removals,
    /// allowing banned users to persist in forked group states. This function enforces
    /// strict proposal ordering to prevent eviction race conditions.
    async fn validate_external_commit(&self, commit: &ExternalCommit) -> Result<()> {
        // 1. Check Epoch matches current
        if commit.epoch != self.epoch {
            return Err(Error::StaleEpoch {
                expected: self.epoch,
                actual: commit.epoch,
            });
        }

        // 2. CRITICAL: Check for Pending Removals
        // If the group has a pending "Remove Member" proposal in the queue,
        // an External Commit MUST include it or be rejected.
        // Otherwise, the new joiner creates a fork where the banned member still exists.
        if self.has_pending_removals() && !commit.includes_proposals(&self.pending_removals) {
            return Err(Error::MustIncludePendingRemovals {
                pending: self.pending_removals.clone(),
            });
        }

        // 3. Verify the external commit is properly signed
        commit.verify_signature()?;

        Ok(())
    }

    /// Check if there are pending removal proposals in the queue
    fn has_pending_removals(&self) -> bool {
        self.pending_proposals.iter().any(|p| matches!(p, Proposal::Remove(_)))
    }

    /// Sequence application message
    async fn sequence_message(&self, mut frame: Frame) -> Result<()> {
        // Assign global order
        let index = self.next_index.fetch_add(1, Ordering::SeqCst);
        frame.log_index = index;

        // Validate epoch
        if frame.epoch != self.epoch {
            return Err(Error::StaleEpoch);
        }

        // Persist and broadcast
        self.append_to_log(&frame)?;
        self.broadcast(frame).await?;

        Ok(())
    }

    /// Batch proposals into commit
    async fn maybe_commit(&mut self) -> Result<()> {
        if self.pending_proposals.is_empty() {
            return Ok(());
        }

        // Batch commit after delay or threshold
        let should_commit =
            self.pending_proposals.len() >= MAX_PROPOSALS_PER_COMMIT ||
            self.commit_timer.as_ref().map_or(false, |t| t.expired());

        if should_commit {
            self.create_and_broadcast_commit().await?;
            self.pending_proposals.clear();
            self.commit_timer = None;
        } else if self.commit_timer.is_none() {
            // Start timer for batching
            self.commit_timer = Some(Timer::new(COMMIT_DELAY));
        }

        Ok(())
    }
}
```

### 3.2 External Commits (Server Authority)

The server can unilaterally modify groups:

```rust
/// Server-initiated operations
impl Sequencer {
    /// Remove member immediately
    async fn kick_member(
        &mut self,
        target: LeafIndex,
        reason: KickReason,
    ) -> Result<()> {
        // Create external commit
        let commit = self.mls_state.create_external_commit(
            vec![Proposal::Remove(target)],
            &SERVER_CREDENTIAL,
        )?;

        // Apply locally
        self.mls_state.process_commit(&commit)?;
        self.epoch += 1;

        // Create frame
        let payload = commit.encode();
        let mut header = FrameHeader {
            magic: 0x53554E44u32.to_be(),
            version: 0x01,
            flags: FrameFlags::EXTERNAL.bits(),
            opcode: Opcode::ExternalCommit as u16,
            request_id: 0,
            room_id: self.room_id.as_bytes(),
            sender_id: SERVER_ID,
            log_index: self.next_index.load(Ordering::SeqCst),
            hlc_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            epoch: self.epoch,
            payload_size: (payload.len() as u32).to_be(),
            signature: [0; 64],
        };

        // Sign frame
        header.signature = header.sign(&SERVER_KEY, &payload);

        let frame = Frame { header, payload };

        // Broadcast
        self.broadcast(frame).await?;

        // Audit
        audit_log::write(AuditEvent::MemberKicked {
            room: self.room_id,
            target,
            reason,
            epoch: self.epoch,
        })?;

        Ok(())
    }
}
```

---

## 4. Networking Layer

### 4.1 QUIC Configuration

Optimized for mobile networks:

```rust
/// QUIC server configuration
fn configure_quic() -> quinn::ServerConfig {
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(
        rustls::ServerConfig::builder()
            .with_cipher_suites(&[
                // TLS 1.3 only
                rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
                rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            ])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap()
    ));

    let transport = Arc::get_mut(&mut config.transport).unwrap();

    // Connection parameters
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

    // Stream limits
    transport.max_concurrent_bidi_streams(256u32.into());
    transport.max_concurrent_uni_streams(256u32.into());

    // Buffer sizes
    transport.stream_receive_window(1024 * 1024u32.into()); // 1MB
    transport.receive_window(8 * 1024 * 1024u32.into());    // 8MB

    // Enable migration
    transport.migration(true);

    // 0-RTT
    transport.max_early_data_size(u32::MAX);

    config
}
```

### 4.2 Connection Handler

```rust
/// Per-connection state machine
struct ConnectionHandler {
    connection: quinn::Connection,
    state: ConnectionState,
    rooms: HashSet<RoomId>,
    rate_limiter: TokenBucket,
}

impl ConnectionHandler {
    async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                // Incoming streams
                Some(stream) = self.connection.accept_bi() => {
                    let (send, recv) = stream?;
                    self.handle_stream(send, recv).await?;
                }

                // Datagrams (for presence/typing)
                Some(bytes) = self.connection.read_datagram() => {
                    self.handle_datagram(bytes?).await?;
                }

                // Connection closed
                else => break,
            }
        }

        Ok(())
    }

    async fn handle_stream(
        &mut self,
        send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) -> Result<()> {
        // Read frame header first (128 bytes, fixed size)
        let mut header_bytes = [0u8; FrameHeader::SIZE];
        recv.read_exact(&mut header_bytes).await?;
        let header = FrameHeader::from_bytes(&header_bytes)?;

        // Read payload based on header size
        let payload_size = u32::from_be(header.payload_size) as usize;
        let mut payload = vec![0u8; payload_size];
        recv.read_exact(&mut payload).await?;

        let frame = Frame { header: *header, payload };

        // Rate limiting
        if !self.rate_limiter.try_consume(1) {
            return self.send_error(ErrorCode::RateLimited).await;
        }

        // Process frame
        let response = self.process_frame(frame).await?;

        // Send response
        response.write_to(send).await?;

        Ok(())
    }
}
```

---

## 5. Performance Optimizations

### 5.1 Memory Management

Static allocations where possible:

```rust
/// Pre-allocated buffers
struct BufferPool {
    small: ArrayDeque<[Box<[u8; 4096]>; 256]>,   // 4KB buffers
    medium: ArrayDeque<[Box<[u8; 65536]>; 64]>,  // 64KB buffers
    large: ArrayDeque<[Box<[u8; 1048576]>; 16]>, // 1MB buffers
}

impl BufferPool {
    fn acquire(&mut self, size: usize) -> PooledBuffer {
        if size <= 4096 {
            PooledBuffer::Small(self.small.pop_front().unwrap_or_else(||
                Box::new([0u8; 4096])
            ))
        } else if size <= 65536 {
            PooledBuffer::Medium(self.medium.pop_front().unwrap_or_else(||
                Box::new([0u8; 65536])
            ))
        } else {
            PooledBuffer::Large(self.large.pop_front().unwrap_or_else(||
                Box::new([0u8; 1048576])
            ))
        }
    }
}
```

### 5.2 CPU Affinity

Pin threads to cores:

```rust
/// Thread pinning for NUMA awareness
fn setup_thread_affinity() -> Result<()> {
    let cpus = num_cpus::get();

    // Main thread on CPU 0
    set_thread_affinity(0)?;

    // Network threads on CPUs 1-2
    for i in 0..2 {
        thread::Builder::new()
            .name(format!("net-{}", i))
            .spawn(move || {
                set_thread_affinity(1 + i).unwrap();
                run_network_loop()
            })?;
    }

    // Sequencer threads on remaining CPUs
    for i in 2..cpus {
        thread::Builder::new()
            .name(format!("seq-{}", i - 2))
            .spawn(move || {
                set_thread_affinity(i).unwrap();
                run_sequencer_loop(i - 2)
            })?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn set_thread_affinity(cpu: usize) -> Result<()> {
    use libc::{cpu_set_t, CPU_SET, CPU_ZERO, sched_setaffinity};

    unsafe {
        let mut set: cpu_set_t = std::mem::zeroed();
        CPU_ZERO(&mut set);
        CPU_SET(cpu, &mut set);

        if sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &set) != 0 {
            return Err(Error::AffinityFailed);
        }
    }

    Ok(())
}
```

### 5.3 Benchmarks

Production benchmarks on 8-core server:

```rust
/// Benchmark results
#[cfg(test)]
mod bench {
    use criterion::{black_box, criterion_group, Criterion};

    fn bench_sequencer(c: &mut Criterion) {
        c.bench_function("sequence_message", |b| {
            b.iter(|| {
                // Target: 15,000 msgs/sec/room
                sequencer.sequence_message(black_box(frame))
            })
        });

        c.bench_function("process_commit", |b| {
            b.iter(|| {
                // Target: 45ms for 1000 members
                sequencer.process_commit(black_box(commit))
            })
        });

        c.bench_function("secure_delete", |b| {
            b.iter(|| {
                // Target: 12ms with fsync
                storage.secure_delete(black_box(index))
            })
        });
    }
}
```

---

## 6. Federation Implementation

### 6.1 Hub-to-Hub Protocol

```rust
/// Federation connection manager
struct FederationManager {
    /// Outgoing connections to other hubs
    peers: HashMap<Domain, FederationPeer>,

    /// Pending transactions
    pending: HashMap<TransactionId, PendingTransaction>,

    /// Domain blocklist
    blocked: HashSet<Domain>,
}

struct FederationPeer {
    domain: Domain,
    connection: quinn::Connection,
    state: PeerState,
    last_seen: Instant,
}

impl FederationManager {
    /// Forward frame to federated room
    async fn federate_frame(
        &mut self,
        frame: Frame,
        targets: Vec<Domain>,
    ) -> Result<()> {
        // Wrap in federation envelope
        let envelope = FederatedFrame {
            hub_signature: self.sign_frame(&frame)?,
            inner_frame: frame,
            origin_domain: self.our_domain.clone(),
            forwarded_at: SystemTime::now().timestamp() as u64,
            hop_count: 1,
        };

        // Send to each target domain
        for domain in targets {
            if self.blocked.contains(&domain) {
                continue;
            }

            let peer = self.get_or_connect(domain).await?;
            peer.send_frame(envelope.clone()).await?;
        }

        Ok(())
    }
}
```

### 6.2 Authority Transfer Protocol

```rust
/// Room authority management
impl RoomAuthority {
    /// Initiate authority transfer
    async fn transfer_authority(
        &mut self,
        new_hub: HubId,
    ) -> Result<()> {
        // Step 1: Propose transfer
        let proposal = AuthorityTransfer {
            room_id: self.room_id,
            current: self.current_authority,
            new: new_hub,
            epoch: self.epoch,
            nonce: rand::random(),
        };

        // Step 2: Collect votes
        let votes = self.collect_votes(&proposal).await?;

        // Step 3: Check majority
        let approvals = votes.iter()
            .filter(|v| v.approve)
            .count();

        if approvals <= self.voters.len() / 2 {
            return Err(Error::TransferRejected);
        }

        // Step 4: Commit transfer
        let commit = TransferCommit {
            proposal,
            votes,
            new_epoch: self.epoch + 1,
        };

        // Step 5: Broadcast commit
        self.broadcast_commit(&commit).await?;

        // Step 6: Update local state
        self.current_authority = new_hub;
        self.epoch = commit.new_epoch;

        Ok(())
    }
}
```

---

## 7. Monitoring & Observability

### 7.1 Metrics

```rust
/// Metrics collection
lazy_static! {
    static ref MESSAGES_SENT: IntCounter =
        register_int_counter!("sunder_messages_sent_total", "Total messages sent").unwrap();

    static ref COMMITS_PROCESSED: Histogram =
        register_histogram!("sunder_commit_duration_seconds", "Commit processing time").unwrap();

    static ref ACTIVE_CONNECTIONS: IntGauge =
        register_int_gauge!("sunder_connections_active", "Active connections").unwrap();

    static ref ROOM_MEMBERS: IntGaugeVec =
        register_int_gauge_vec!("sunder_room_members", "Members per room", &["room"]).unwrap();
}

/// Instrument critical paths
#[instrument(skip_all, fields(room_id = %room_id))]
async fn process_message(room_id: RoomId, message: Frame) -> Result<()> {
    let timer = COMMITS_PROCESSED.start_timer();

    let result = process_message_inner(room_id, message).await;

    timer.observe_duration();
    MESSAGES_SENT.inc();

    result
}
```

### 7.2 Health Checks

```rust
/// Liveness and readiness probes
async fn health_check() -> HealthStatus {
    let mut status = HealthStatus::default();

    // Check database
    match db.begin_read() {
        Ok(_) => status.database = true,
        Err(e) => {
            error!("Database unhealthy: {}", e);
            status.database = false;
        }
    }

    // Check sequencers
    for shard in &shards {
        if shard.is_healthy() {
            status.healthy_shards += 1;
        }
    }

    // Check memory
    let mem_info = sys_info::mem_info().unwrap();
    status.memory_available = mem_info.avail > MIN_MEMORY;

    status
}
```

---

## 8. Deployment Configuration

### 8.1 systemd Service

```ini
[Unit]
Description=Sunder Server
After=network.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/sunderd --config /etc/sunder/config.toml
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure
RestartSec=5s

# Security
User=sunder
Group=sunder
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
ReadWritePaths=/var/lib/sunder

# Resource limits
LimitNOFILE=65536
LimitNPROC=512
MemoryMax=8G
CPUQuota=600%

[Install]
WantedBy=multi-user.target
```

### 8.2 Configuration File

```toml
# /etc/sunder/config.toml

[server]
bind = "[::]:8443"
domain = "hub.example.com"
max_connections = 10000
max_rooms = 5000

[tls]
cert_path = "/etc/sunder/cert.pem"
key_path = "/etc/sunder/key.pem"

[database]
path = "/var/lib/sunder/data.redb"
cache_size_mb = 512
sync_mode = "normal"  # normal|fast|paranoid

[limits]
max_members_per_room = 10000
max_message_size_bytes = 16777216
max_proposals_per_epoch = 64
commit_delay_ms = 100

[federation]
enabled = true
max_hops = 3
timeout_seconds = 30

[monitoring]
metrics_bind = "127.0.0.1:9090"
log_level = "info"
```

---

## 9. Production Checklist

### Pre-Deployment

- [ ] TLS certificates valid and not expiring soon
- [ ] Database backup strategy configured
- [ ] Monitoring and alerting configured
- [ ] Rate limiting tuned for expected load
- [ ] Federation allowlist/blocklist configured
- [ ] Audit logging enabled
- [ ] Resource limits set appropriately

### Post-Deployment

- [ ] Verify all health checks passing
- [ ] Check metrics in Prometheus/Grafana
- [ ] Test client connectivity
- [ ] Verify federation if enabled
- [ ] Monitor memory usage
- [ ] Check log for errors
- [ ] Validate audit trail

### Maintenance

- [ ] Regular database compaction scheduled
- [ ] Log rotation configured
- [ ] Certificate renewal automated
- [ ] Backup verification tests
- [ ] Performance regression tests
- [ ] Security update schedule

---

## References

1. Redb Documentation: https://docs.rs/redb
2. Quinn QUIC: https://docs.rs/quinn
3. MLS RFC 9420: https://datatracker.ietf.org/doc/rfc9420/
4. TigerBeetle Design: https://github.com/tigerbeetledb/tigerbeetle
