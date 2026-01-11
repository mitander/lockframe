//! Standard invariant checks.
//!
//! These invariants capture behavioral properties that must always hold.
//! They verify WHAT must be true, not specific test scenarios.

use std::collections::{HashMap, HashSet};

use super::{Invariant, InvariantResult, SystemSnapshot, Violation};

/// Active room must exist in rooms map.
///
/// If `active_room` is `Some(room_id)`, then `rooms` must contain `room_id`.
/// This prevents the UI from showing a selected room that doesn't exist.
pub struct ActiveRoomInRooms;

impl Invariant for ActiveRoomInRooms {
    fn name(&self) -> &'static str {
        "active_room_in_rooms"
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        for client in &state.clients {
            if let Some(active) = client.active_room {
                if !client.rooms.contains_key(&active) {
                    return Err(Violation {
                        invariant: self.name(),
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
    fn name(&self) -> &'static str {
        "epoch_monotonicity"
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        for client in &state.clients {
            for (room_id, history) in &client.epoch_history {
                for window in history.windows(2) {
                    if window[1] < window[0] {
                        return Err(Violation {
                            invariant: self.name(),
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
    fn name(&self) -> &'static str {
        "membership_consistency"
    }

    fn check(&self, state: &SystemSnapshot) -> InvariantResult {
        // Group clients by (room_id, epoch) and compare their member sets
        let mut room_epoch_members: HashMap<(u128, u64), Vec<(u64, HashSet<u64>)>> = HashMap::new();

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
                        invariant: self.name(),
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
    fn name(&self) -> &'static str {
        "tree_hash_convergence"
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
                    invariant: self.name(),
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
        client.record_epoch(100, 3); // Decreased!

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
        let room2 = RoomSnapshot::with_epoch(1).with_members([10, 30]); // Different!

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
        let room2 = RoomSnapshot::with_epoch(1).with_tree_hash([2u8; 32]); // Different!

        let client1 = ClientSnapshot::new(10).with_room(100, room1);
        let client2 = ClientSnapshot::new(20).with_room(100, room2);

        let snapshot = SystemSnapshot::from_clients(vec![client1, client2]);
        let result = TreeHashConvergence.check(&snapshot);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("2 distinct"));
    }
}
