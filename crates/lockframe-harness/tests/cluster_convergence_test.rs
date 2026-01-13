//! Cluster convergence tests using Deterministic Simulation Testing.
//!
//! # Limitations
//!
//! Mixed join methods (Welcome then External or vice versa) require server-side
//! GroupInfo management that this test harness doesn't fully simulate. Those
//! flows are tested in the actual server integration tests.

use lockframe_client::{Client, ClientAction, ClientEvent, ClientIdentity};
use lockframe_core::mls::RoomId;
use lockframe_harness::SimEnv;
use lockframe_proto::{FrameHeader, Opcode, Payload, payloads::mls::GroupInfoPayload};
use proptest::prelude::*;

const ROOM_ID: RoomId = 0x0001_0001_0001_0001_0001_0001_0001_0001;

/// Simulated cluster of clients for testing convergence.
struct TestCluster {
    clients: Vec<Client<SimEnv>>,
    /// Current GroupInfo bytes for external joiners
    group_info: Option<Vec<u8>>,
}

impl TestCluster {
    fn new(seed: u64, num_clients: usize) -> Self {
        let env = SimEnv::with_seed(seed);
        let clients = (0..num_clients)
            .map(|i| {
                let identity = ClientIdentity::new(i as u64 + 1);
                Client::new(env.clone(), identity)
            })
            .collect();

        Self { clients, group_info: None }
    }

    /// First client creates the room.
    fn create_room(&mut self) -> Result<(), String> {
        let actions = self.clients[0]
            .handle(ClientEvent::CreateRoom { room_id: ROOM_ID })
            .map_err(|e| format!("create room failed: {e}"))?;

        for action in &actions {
            if let ClientAction::Send(frame) = action {
                if frame.header.opcode_enum() == Some(Opcode::GroupInfo) {
                    if let Ok(Payload::GroupInfo(payload)) = Payload::from_frame(frame.clone()) {
                        self.group_info = Some(payload.group_info_bytes);
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a client via Welcome (existing member adds them).
    fn join_via_welcome(&mut self, joiner_idx: usize) -> Result<(), String> {
        let (kp_bytes, _) = self.clients[joiner_idx]
            .generate_key_package()
            .map_err(|e| format!("keygen failed: {e}"))?;

        let add_actions = self.clients[0]
            .handle(ClientEvent::AddMembers { room_id: ROOM_ID, key_packages: vec![kp_bytes] })
            .map_err(|e| format!("add member failed: {e}"))?;

        let mut welcome_frame = None;
        let mut commit_frame = None;
        for action in &add_actions {
            if let ClientAction::Send(frame) = action {
                match frame.header.opcode_enum() {
                    Some(Opcode::Welcome) => welcome_frame = Some(frame.clone()),
                    Some(Opcode::Commit) => commit_frame = Some(frame.clone()),
                    _ => {},
                }
            }
        }

        let welcome = welcome_frame.ok_or("no Welcome frame")?;
        let commit = commit_frame.ok_or("no Commit frame")?;

        self.clients[0]
            .handle(ClientEvent::FrameReceived(commit.clone()))
            .map_err(|e| format!("creator commit failed: {e}"))?;

        self.clients[joiner_idx]
            .handle(ClientEvent::JoinRoom { room_id: ROOM_ID, welcome: welcome.payload.to_vec() })
            .map_err(|e| format!("join via welcome failed: {e}"))?;

        for (i, client) in self.clients.iter_mut().enumerate() {
            if i == 0 || i == joiner_idx {
                continue;
            }
            if client.is_member(ROOM_ID) {
                let _ = client.handle(ClientEvent::FrameReceived(commit.clone()));
            }
        }

        Ok(())
    }

    /// Add a client via external commit.
    fn join_via_external(&mut self, joiner_idx: usize) -> Result<(), String> {
        let group_info_bytes = self.group_info.as_ref().ok_or("no GroupInfo available")?;

        self.clients[joiner_idx]
            .handle(ClientEvent::ExternalJoin { room_id: ROOM_ID })
            .map_err(|e| format!("external join init failed: {e}"))?;

        let current_epoch = self.clients[0].epoch(ROOM_ID).unwrap_or(0);
        let payload = GroupInfoPayload {
            room_id: ROOM_ID,
            epoch: current_epoch,
            group_info_bytes: group_info_bytes.clone(),
        };
        let gi_frame = Payload::GroupInfo(payload)
            .into_frame(FrameHeader::new(Opcode::GroupInfo))
            .map_err(|e| format!("GroupInfo frame failed: {e}"))?;

        let join_actions = self.clients[joiner_idx]
            .handle(ClientEvent::FrameReceived(gi_frame))
            .map_err(|e| format!("process GroupInfo failed: {e}"))?;

        let mut ext_commit = None;
        let mut new_group_info = None;
        for action in &join_actions {
            if let ClientAction::Send(frame) = action {
                match frame.header.opcode_enum() {
                    Some(Opcode::Commit) | Some(Opcode::ExternalCommit) => {
                        ext_commit = Some(frame.clone());
                    },
                    Some(Opcode::GroupInfo) => {
                        if let Ok(Payload::GroupInfo(gi)) = Payload::from_frame(frame.clone()) {
                            new_group_info = Some(gi.group_info_bytes);
                        }
                    },
                    _ => {},
                }
            }
        }

        let commit = ext_commit.ok_or("no external commit frame")?;

        for (i, client) in self.clients.iter_mut().enumerate() {
            if i == joiner_idx {
                continue;
            }
            if client.is_member(ROOM_ID) {
                let _ = client.handle(ClientEvent::FrameReceived(commit.clone()));
            }
        }

        if let Some(gi) = new_group_info {
            self.group_info = Some(gi);
        }

        Ok(())
    }

    /// Send message and verify delivery.
    fn send_and_verify(&mut self, sender_idx: usize, message: &[u8]) -> Result<(), String> {
        let sender_id = self.clients[sender_idx].sender_id();

        let send_actions = self.clients[sender_idx]
            .handle(ClientEvent::SendMessage { room_id: ROOM_ID, plaintext: message.to_vec() })
            .map_err(|e| format!("send failed: {e}"))?;

        let msg_frame = send_actions
            .iter()
            .filter_map(|a| match a {
                ClientAction::Send(f) if f.header.opcode_enum() == Some(Opcode::AppMessage) => {
                    Some(f.clone())
                },
                _ => None,
            })
            .next()
            .ok_or("no message frame")?;

        for (i, client) in self.clients.iter_mut().enumerate() {
            if i == sender_idx || !client.is_member(ROOM_ID) {
                continue;
            }

            let recv_actions = client
                .handle(ClientEvent::FrameReceived(msg_frame.clone()))
                .map_err(|e| format!("client {i} receive failed: {e}"))?;

            let delivered = recv_actions.iter().any(|a| {
                matches!(a, ClientAction::DeliverMessage { sender_id: s, plaintext, .. }
                    if *s == sender_id && plaintext == message)
            });

            if !delivered {
                return Err(format!("client {i} did not receive message"));
            }
        }

        Ok(())
    }

    /// Get epochs for all room members.
    fn epochs(&self) -> Vec<(usize, u64)> {
        self.clients
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.epoch(ROOM_ID).map(|e| (i, e)))
            .collect()
    }
}

/// Verify all clients have converged to the same epoch.
fn verify_convergence(cluster: &TestCluster) -> Result<(), String> {
    let epochs = cluster.epochs();
    if epochs.is_empty() {
        return Err("no clients in room".to_string());
    }

    let first = epochs[0].1;
    for (idx, epoch) in &epochs {
        if *epoch != first {
            return Err(format!(
                "epoch mismatch: client 0 at {}, client {} at {}",
                first, idx, epoch
            ));
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// Verifies that Welcome-based joins scale correctly. Regardless of how many
    /// clients join via Welcome, all should converge and be able to message.
    #[test]
    fn prop_welcome_joins_converge(
        seed in 1u64..10000,
        num_joiners in 1usize..4,
    ) {
        let mut cluster = TestCluster::new(seed, 1 + num_joiners);

        cluster.create_room().expect("create");

        for i in 1..=num_joiners {
            cluster.join_via_welcome(i)
                .unwrap_or_else(|e| panic!("join {} failed: {}", i, e));
        }

        // ORACLE: All converged
        verify_convergence(&cluster).expect("convergence");

        // ORACLE: Messaging works
        cluster.send_and_verify(0, b"test").expect("messaging");
    }

    /// Verifies that external joins scale correctly. Multiple clients joining
    /// via external commit should all converge to the same epoch.
    #[test]
    fn prop_external_joins_converge(
        seed in 1u64..10000,
        num_joiners in 1usize..4,
    ) {
        let mut cluster = TestCluster::new(seed, 1 + num_joiners);

        cluster.create_room().expect("create");

        for i in 1..=num_joiners {
            cluster.join_via_external(i)
                .unwrap_or_else(|e| panic!("join {} failed: {}", i, e));
        }

        // ORACLE: All converged
        verify_convergence(&cluster).expect("convergence");

        // ORACLE: Messaging works from each client
        for sender in 0..=num_joiners {
            let msg = format!("from {}", sender);
            cluster.send_and_verify(sender, msg.as_bytes()).expect("messaging");
        }
    }
}

/// WHY THIS TEST IS NEEDED:
/// Baseline test for two clients - creator and one joiner via Welcome.
/// If this fails, the basic Welcome flow is broken.
#[test]
fn regression_two_clients_welcome() {
    let mut cluster = TestCluster::new(42, 2);
    cluster.create_room().expect("create");
    cluster.join_via_welcome(1).expect("join");
    verify_convergence(&cluster).expect("convergence");
    cluster.send_and_verify(0, b"hello").expect("msg from creator");
    cluster.send_and_verify(1, b"world").expect("msg from joiner");
}

/// WHY THIS TEST IS NEEDED:
/// Baseline test for two clients - creator and one joiner via external commit.
/// If this fails, the basic external join flow is broken.
#[test]
fn regression_two_clients_external() {
    let mut cluster = TestCluster::new(42, 2);
    cluster.create_room().expect("create");
    cluster.join_via_external(1).expect("join");
    verify_convergence(&cluster).expect("convergence");
    cluster.send_and_verify(0, b"hello").expect("msg from creator");
    cluster.send_and_verify(1, b"world").expect("msg from joiner");
}

/// WHY THIS TEST IS NEEDED:
/// Three clients all joining via external commit - tests sequential external
/// joins which require proper GroupInfo updates after each commit.
#[test]
fn regression_three_clients_all_external() {
    let mut cluster = TestCluster::new(42, 3);
    cluster.create_room().expect("create");
    cluster.join_via_external(1).expect("join 1");
    cluster.join_via_external(2).expect("join 2");
    verify_convergence(&cluster).expect("convergence");
    cluster.send_and_verify(0, b"from creator").expect("msg 0");
    cluster.send_and_verify(1, b"from joiner 1").expect("msg 1");
    cluster.send_and_verify(2, b"from joiner 2").expect("msg 2");
}
