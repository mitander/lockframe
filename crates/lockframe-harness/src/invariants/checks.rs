//! Standard invariant checks.
//!
//! These invariants capture behavioral properties that must always hold.
//! They verify WHAT must be true, not specific test scenarios.

use std::collections::{BTreeSet, HashMap, HashSet};

use super::{Invariant, InvariantKind, InvariantResult, SystemSnapshot, Violation};

/// Active room must exist in rooms map.
///
/// If `active_room` is `Some(room_id)`, then `rooms` must contain `room_id`.
/// This prevents the UI from showing a selected room that doesn't exist.
pub struct ActiveRoomInRooms;

impl Invariant for ActiveRoomInRooms {
    fn kind(&self) -> InvariantKind {
        InvariantKind::ActiveRoomInRooms
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        for client in &state.clients {
            if let Some(active) = client.active_room {
                if !client.rooms.contains_key(&active) {
                    return Err(Violation {
                        invariant: self.kind(),
                        message: format!(
                            "client {}: active_room {} not in rooms {:?}",
                            client.id,
                            active,
                            client.rooms.keys().collect::<Vec<_>>()
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Epochs must never decrease within a client's history.
///
/// For any room, observed epochs should be monotonically increasing.
/// A decreasing epoch indicates a protocol violation or state corruption.
pub struct EpochMonotonicity;

impl Invariant for EpochMonotonicity {
    fn kind(&self) -> InvariantKind {
        InvariantKind::EpochMonotonicity
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        for client in &state.clients {
            for (room_id, history) in &client.epoch_history {
                for window in history.windows(2) {
                    if window[1] < window[0] {
                        return Err(Violation {
                            invariant: self.kind(),
                            message: format!(
                                "client {} room {}: epoch decreased {} → {}",
                                client.id, room_id, window[0], window[1]
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

/// Members of the same room at the same epoch must agree on membership.
///
/// All clients in a room at the same epoch should see the same member set.
/// Divergent membership views indicate a synchronization bug.
pub struct MembershipConsistency;

impl Invariant for MembershipConsistency {
    fn kind(&self) -> InvariantKind {
        InvariantKind::MembershipConsistency
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        // Group clients by (room_id, epoch) and compare their member sets
        let mut room_epoch_members: HashMap<(u128, u64), Vec<(u64, BTreeSet<u64>)>> =
            HashMap::new();

        for client in &state.clients {
            for (room_id, room) in &client.rooms {
                room_epoch_members
                    .entry((*room_id, room.epoch))
                    .or_default()
                    .push((client.id, room.members.clone()));
            }
        }

        for ((room_id, epoch), clients) in room_epoch_members {
            if clients.len() < 2 {
                continue; // Need at least 2 clients to compare
            }

            let first_members = &clients[0].1;
            for (client_id, members) in &clients[1..] {
                if members != first_members {
                    return Err(Violation {
                        invariant: self.kind(),
                        message: format!(
                            "room {} epoch {}: client {} sees members {:?}, client {} sees {:?}",
                            room_id, epoch, clients[0].0, first_members, client_id, members
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Tree hashes must converge at the same epoch.
///
/// All clients at the same epoch in the same room must have identical
/// tree hashes. Divergent hashes indicate a cryptographic state mismatch.
pub struct TreeHashConvergence;

impl Invariant for TreeHashConvergence {
    fn kind(&self) -> InvariantKind {
        InvariantKind::TreeHashConvergence
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        // Group clients by (room_id, epoch) and compare tree hashes
        let mut room_epoch_hashes: HashMap<(u128, u64), Vec<(u64, [u8; 32])>> = HashMap::new();

        for client in &state.clients {
            for (room_id, room) in &client.rooms {
                room_epoch_hashes
                    .entry((*room_id, room.epoch))
                    .or_default()
                    .push((client.id, room.tree_hash));
            }
        }

        for ((room_id, epoch), clients) in room_epoch_hashes {
            let unique_hashes: HashSet<_> = clients.iter().map(|(_, h)| h).collect();
            if unique_hashes.len() > 1 {
                return Err(Violation {
                    invariant: self.kind(),
                    message: format!(
                        "room {} epoch {}: {} distinct tree hashes among {} clients",
                        room_id,
                        epoch,
                        unique_hashes.len(),
                        clients.len()
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Log indices must have no gaps.
///
/// For each room, if a client has received messages with log indices,
/// those indices should be sequential with no gaps (0, 1, 2, ...).
/// Gaps indicate message loss or reordering at the storage layer.
pub struct NoLogGaps;

impl Invariant for NoLogGaps {
    fn kind(&self) -> InvariantKind {
        InvariantKind::NoLogGaps
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        for client in &state.clients {
            for (room_id, room) in &client.rooms {
                if room.log_indices.is_empty() {
                    continue;
                }

                let mut sorted = room.log_indices.clone();
                sorted.sort_unstable();

                for (i, &idx) in sorted.iter().enumerate() {
                    if idx != i as u64 {
                        return Err(Violation {
                            invariant: self.kind(),
                            message: format!(
                                "client {} room {}: gap at position {}, expected {}, got {}",
                                client.id, room_id, i, i, idx
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

/// All clients must observe the same total ordering of messages.
///
/// For clients in the same room who have received the same log indices,
/// the ordering of those indices should be identical. Divergent orderings
/// indicate a protocol violation or message reordering bug.
pub struct TotalOrdering;

impl Invariant for TotalOrdering {
    fn kind(&self) -> InvariantKind {
        InvariantKind::TotalOrdering
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        // Group clients by room and compare their log index sequences
        let mut room_orderings: HashMap<u128, Vec<(u64, Vec<u64>)>> = HashMap::new();

        for client in &state.clients {
            for (room_id, room) in &client.rooms {
                if room.log_indices.is_empty() {
                    continue;
                }
                room_orderings
                    .entry(*room_id)
                    .or_default()
                    .push((client.id, room.log_indices.clone()));
            }
        }

        for (room_id, orderings) in room_orderings {
            if orderings.len() < 2 {
                continue; // Need at least 2 clients
            }

            // Find common indices between all clients
            let mut common_indices: HashSet<u64> = orderings[0].1.iter().copied().collect();
            for (_, indices) in &orderings[1..] {
                let other: HashSet<u64> = indices.iter().copied().collect();
                common_indices = common_indices.intersection(&other).copied().collect();
            }

            if common_indices.is_empty() {
                continue; // Nothing to compare
            }

            // We need the common indices to be in relative order
            let first_common_order: Vec<u64> =
                orderings[0].1.iter().filter(|i| common_indices.contains(i)).copied().collect();

            for (client_id, indices) in &orderings[1..] {
                let client_common_order: Vec<u64> =
                    indices.iter().filter(|i| common_indices.contains(i)).copied().collect();

                if client_common_order != first_common_order {
                    return Err(Violation {
                        invariant: self.kind(),
                        message: format!(
                            "room {}: client {} sees order {:?}, client {} sees {:?}",
                            room_id,
                            orderings[0].0,
                            first_common_order,
                            client_id,
                            client_common_order
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariants::{ClientSnapshot, RoomSnapshot};

    #[test]
    fn active_room_in_rooms_passes_when_valid() {
        let room = RoomSnapshot::with_epoch(1);
        let client = ClientSnapshot::new(1).with_active_room(Some(100)).with_room(100, room);

        let snapshot = SystemSnapshot::single(client);
        assert!(ActiveRoomInRooms.check(&snapshot).is_ok());
    }

    #[test]
    fn active_room_in_rooms_fails_when_missing() {
        let client = ClientSnapshot::new(1).with_active_room(Some(999));

        let snapshot = SystemSnapshot::single(client);
        let result = ActiveRoomInRooms.check(&snapshot);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("999"));
    }

    #[test]
    fn active_room_none_always_passes() {
        let client = ClientSnapshot::new(1).with_active_room(None);

        let snapshot = SystemSnapshot::single(client);
        assert!(ActiveRoomInRooms.check(&snapshot).is_ok());
    }

    #[test]
    fn epoch_monotonicity_passes_when_increasing() {
        let mut client = ClientSnapshot::new(1);
        client.record_epoch(100, 1);
        client.record_epoch(100, 2);
        client.record_epoch(100, 5);

        let snapshot = SystemSnapshot::single(client);
        assert!(EpochMonotonicity.check(&snapshot).is_ok());
    }

    #[test]
    fn epoch_monotonicity_fails_when_decreasing() {
        let mut client = ClientSnapshot::new(1);
        client.record_epoch(100, 5);
        client.record_epoch(100, 3); // Decreased

        let snapshot = SystemSnapshot::single(client);
        let result = EpochMonotonicity.check(&snapshot);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("5 → 3"));
    }

    #[test]
    fn membership_consistency_passes_when_same() {
        let room1 = RoomSnapshot::with_epoch(1).with_members([10, 20]);
        let room2 = RoomSnapshot::with_epoch(1).with_members([10, 20]);

        let client1 = ClientSnapshot::new(10).with_room(100, room1);
        let client2 = ClientSnapshot::new(20).with_room(100, room2);

        let snapshot = SystemSnapshot::from_clients(vec![client1, client2]);
        assert!(MembershipConsistency.check(&snapshot).is_ok());
    }

    #[test]
    fn membership_consistency_fails_when_different() {
        let room1 = RoomSnapshot::with_epoch(1).with_members([10, 20]);
        let room2 = RoomSnapshot::with_epoch(1).with_members([10, 30]); // Different

        let client1 = ClientSnapshot::new(10).with_room(100, room1);
        let client2 = ClientSnapshot::new(20).with_room(100, room2);

        let snapshot = SystemSnapshot::from_clients(vec![client1, client2]);
        let result = MembershipConsistency.check(&snapshot);
        assert!(result.is_err());
    }

    #[test]
    fn tree_hash_convergence_passes_when_same() {
        let hash = [42u8; 32];
        let room1 = RoomSnapshot::with_epoch(1).with_tree_hash(hash);
        let room2 = RoomSnapshot::with_epoch(1).with_tree_hash(hash);

        let client1 = ClientSnapshot::new(10).with_room(100, room1);
        let client2 = ClientSnapshot::new(20).with_room(100, room2);

        let snapshot = SystemSnapshot::from_clients(vec![client1, client2]);
        assert!(TreeHashConvergence.check(&snapshot).is_ok());
    }

    #[test]
    fn tree_hash_convergence_fails_when_different() {
        let room1 = RoomSnapshot::with_epoch(1).with_tree_hash([1u8; 32]);
        let room2 = RoomSnapshot::with_epoch(1).with_tree_hash([2u8; 32]); // Different

        let client1 = ClientSnapshot::new(10).with_room(100, room1);
        let client2 = ClientSnapshot::new(20).with_room(100, room2);

        let snapshot = SystemSnapshot::from_clients(vec![client1, client2]);
        let result = TreeHashConvergence.check(&snapshot);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("2 distinct"));
    }

    #[test]
    fn no_log_gaps_passes_when_sequential() {
        let room = RoomSnapshot::with_epoch(1).with_log_indices([0, 1, 2, 3, 4]);
        let client = ClientSnapshot::new(1).with_room(100, room);

        let snapshot = SystemSnapshot::single(client);
        assert!(NoLogGaps.check(&snapshot).is_ok());
    }

    #[test]
    fn no_log_gaps_fails_when_gap_exists() {
        let room = RoomSnapshot::with_epoch(1).with_log_indices([0, 1, 3, 4]); // Gap at 2
        let client = ClientSnapshot::new(1).with_room(100, room);

        let snapshot = SystemSnapshot::single(client);
        let result = NoLogGaps.check(&snapshot);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("gap"));
    }

    #[test]
    fn no_log_gaps_passes_when_empty() {
        let room = RoomSnapshot::with_epoch(1);
        let client = ClientSnapshot::new(1).with_room(100, room);

        let snapshot = SystemSnapshot::single(client);
        assert!(NoLogGaps.check(&snapshot).is_ok());
    }

    #[test]
    fn total_ordering_passes_when_same_order() {
        let room1 = RoomSnapshot::with_epoch(1).with_log_indices([0, 1, 2]);
        let room2 = RoomSnapshot::with_epoch(1).with_log_indices([0, 1, 2]);

        let client1 = ClientSnapshot::new(10).with_room(100, room1);
        let client2 = ClientSnapshot::new(20).with_room(100, room2);

        let snapshot = SystemSnapshot::from_clients(vec![client1, client2]);
        assert!(TotalOrdering.check(&snapshot).is_ok());
    }

    #[test]
    fn total_ordering_fails_when_different_order() {
        let room1 = RoomSnapshot::with_epoch(1).with_log_indices([0, 1, 2]);
        let room2 = RoomSnapshot::with_epoch(1).with_log_indices([0, 2, 1]); // Different order

        let client1 = ClientSnapshot::new(10).with_room(100, room1);
        let client2 = ClientSnapshot::new(20).with_room(100, room2);

        let snapshot = SystemSnapshot::from_clients(vec![client1, client2]);
        let result = TotalOrdering.check(&snapshot);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("order"));
    }

    #[test]
    fn total_ordering_ignores_different_rooms() {
        let room1 = RoomSnapshot::with_epoch(1).with_log_indices([0, 1, 2]);
        let room2 = RoomSnapshot::with_epoch(1).with_log_indices([2, 1, 0]); // Different room

        let client1 = ClientSnapshot::new(10).with_room(100, room1);
        let client2 = ClientSnapshot::new(20).with_room(200, room2); // Different room

        let snapshot = SystemSnapshot::from_clients(vec![client1, client2]);
        assert!(TotalOrdering.check(&snapshot).is_ok());
    }
}
