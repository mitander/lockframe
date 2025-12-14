//! Connection registry for session and room subscription tracking.
//!
//! The registry maintains bidirectional mappings between sessions and rooms:
//! - `room → sessions`: Which sessions are subscribed to a room (for broadcast)
//! - `session → rooms`: Which rooms a session is in (for cleanup on disconnect)
//!
//! # Design
//!
//! - Bidirectional mapping: Enables O(1) lookups in both directions
//! - Explicit subscription: No lazy room creation (per CLAUDE.md)
//! - Cleanup on disconnect: Unregistering a session removes all subscriptions

use std::collections::{HashMap, HashSet};

/// Information about a registered session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// User ID associated with this session (after authentication)
    pub user_id: Option<u64>,
    /// Whether the session has completed handshake
    pub authenticated: bool,
}

impl Default for SessionInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionInfo {
    /// Create a new unauthenticated session info.
    pub fn new() -> Self {
        Self { user_id: None, authenticated: false }
    }

    /// Create an authenticated session info with user ID.
    pub fn authenticated(user_id: u64) -> Self {
        Self { user_id: Some(user_id), authenticated: true }
    }
}

/// Registry for tracking sessions and room subscriptions.
///
/// Maintains bidirectional mappings for efficient lookups:
/// - Get all sessions in a room (for broadcast)
/// - Get all rooms a session is in (for cleanup)
#[derive(Debug, Default)]
pub struct ConnectionRegistry {
    /// Session ID → session info
    sessions: HashMap<u64, SessionInfo>,
    /// Room ID → set of subscribed session IDs
    room_subscriptions: HashMap<u128, HashSet<u64>>,
    /// Session ID → set of subscribed room IDs
    session_rooms: HashMap<u64, HashSet<u128>>,
}

impl ConnectionRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new session.
    ///
    /// Returns `false` if session already exists.
    pub fn register_session(&mut self, session_id: u64, info: SessionInfo) -> bool {
        if self.sessions.contains_key(&session_id) {
            return false;
        }
        self.sessions.insert(session_id, info);
        self.session_rooms.insert(session_id, HashSet::new());
        true
    }

    /// Unregister a session and remove all its room subscriptions.
    ///
    /// Returns the session info if it existed, along with the rooms it was in.
    pub fn unregister_session(&mut self, session_id: u64) -> Option<(SessionInfo, HashSet<u128>)> {
        let info = self.sessions.remove(&session_id)?;
        let rooms = self.session_rooms.remove(&session_id).unwrap_or_default();

        for room_id in &rooms {
            if let Some(subscribers) = self.room_subscriptions.get_mut(room_id) {
                subscribers.remove(&session_id);
                if subscribers.is_empty() {
                    self.room_subscriptions.remove(room_id);
                }
            }
        }

        Some((info, rooms))
    }

    /// Get session info by ID.
    pub fn sessions(&self, session_id: u64) -> Option<&SessionInfo> {
        self.sessions.get(&session_id)
    }

    /// Get mutable session info by ID.
    pub fn sessions_mut(&mut self, session_id: u64) -> Option<&mut SessionInfo> {
        self.sessions.get_mut(&session_id)
    }

    /// Check if a session is registered.
    pub fn has_session(&self, session_id: u64) -> bool {
        self.sessions.contains_key(&session_id)
    }

    /// Subscribe a session to a room.
    ///
    /// Returns `false` if the session is not registered.
    pub fn subscribe(&mut self, session_id: u64, room_id: u128) -> bool {
        if !self.sessions.contains_key(&session_id) {
            return false;
        }

        self.room_subscriptions.entry(room_id).or_default().insert(session_id);
        self.session_rooms.entry(session_id).or_default().insert(room_id);
        true
    }

    /// Unsubscribe a session from a room.
    ///
    /// Returns `true` if the session was subscribed and is now unsubscribed.
    pub fn unsubscribe(&mut self, session_id: u64, room_id: u128) -> bool {
        let removed_from_room =
            self.room_subscriptions.get_mut(&room_id).is_some_and(|s| s.remove(&session_id));

        let removed_from_session =
            self.session_rooms.get_mut(&session_id).is_some_and(|r| r.remove(&room_id));

        if self.room_subscriptions.get(&room_id).is_some_and(HashSet::is_empty) {
            self.room_subscriptions.remove(&room_id);
        }

        removed_from_room && removed_from_session
    }

    /// Check if a session is subscribed to a room.
    pub fn is_subscribed(&self, session_id: u64, room_id: u128) -> bool {
        self.room_subscriptions.get(&room_id).is_some_and(|s| s.contains(&session_id))
    }

    /// Get all sessions subscribed to a room.
    pub fn sessions_in_room(&self, room_id: u128) -> impl Iterator<Item = u64> + '_ {
        self.room_subscriptions.get(&room_id).into_iter().flat_map(|s| s.iter().copied())
    }

    /// Get all rooms a session is subscribed to.
    pub fn rooms_for_session(&self, session_id: u64) -> impl Iterator<Item = u128> + '_ {
        self.session_rooms.get(&session_id).into_iter().flat_map(|r| r.iter().copied())
    }

    /// Get total number of registered sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get number of sessions in a specific room.
    pub fn room_session_count(&self, room_id: u128) -> usize {
        self.room_subscriptions.get(&room_id).map_or(0, HashSet::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_lookup_session() {
        let mut registry = ConnectionRegistry::new();

        assert!(registry.register_session(1, SessionInfo::new()));
        assert!(registry.has_session(1));
        assert!(!registry.has_session(2));

        let info = registry.sessions(1).unwrap();
        assert!(!info.authenticated);
        assert!(info.user_id.is_none());
    }

    #[test]
    fn register_duplicate_session_fails() {
        let mut registry = ConnectionRegistry::new();

        assert!(registry.register_session(1, SessionInfo::new()));
        assert!(!registry.register_session(1, SessionInfo::new()));
    }

    #[test]
    fn unregister_session_returns_info() {
        let mut registry = ConnectionRegistry::new();

        registry.register_session(1, SessionInfo::authenticated(42));

        let (info, rooms) = registry.unregister_session(1).unwrap();
        assert!(info.authenticated);
        assert_eq!(info.user_id, Some(42));
        assert!(rooms.is_empty());

        assert!(!registry.has_session(1));
    }

    #[test]
    fn subscribe_and_lookup() {
        let mut registry = ConnectionRegistry::new();
        let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;

        registry.register_session(1, SessionInfo::new());
        registry.register_session(2, SessionInfo::new());

        assert!(registry.subscribe(1, room_id));
        assert!(registry.subscribe(2, room_id));

        assert!(registry.is_subscribed(1, room_id));
        assert!(registry.is_subscribed(2, room_id));

        let sessions: Vec<_> = registry.sessions_in_room(room_id).collect();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.contains(&1));
        assert!(sessions.contains(&2));
    }

    #[test]
    fn subscribe_unregistered_session_fails() {
        let mut registry = ConnectionRegistry::new();
        let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;

        assert!(!registry.subscribe(999, room_id));
    }

    #[test]
    fn unsubscribe_removes_from_both_maps() {
        let mut registry = ConnectionRegistry::new();
        let room_id = 0x1234_5678_90ab_cdef_1234_5678_90ab_cdef;

        registry.register_session(1, SessionInfo::new());
        registry.subscribe(1, room_id);

        assert!(registry.unsubscribe(1, room_id));
        assert!(!registry.is_subscribed(1, room_id));

        let sessions: Vec<_> = registry.sessions_in_room(room_id).collect();
        assert!(sessions.is_empty());

        let rooms: Vec<_> = registry.rooms_for_session(1).collect();
        assert!(rooms.is_empty());
    }

    #[test]
    fn unregister_session_removes_all_subscriptions() {
        let mut registry = ConnectionRegistry::new();
        let room1 = 0x1111_1111_1111_1111_1111_1111_1111_1111;
        let room2 = 0x2222_2222_2222_2222_2222_2222_2222_2222;

        registry.register_session(1, SessionInfo::new());
        registry.register_session(2, SessionInfo::new());

        registry.subscribe(1, room1);
        registry.subscribe(1, room2);
        registry.subscribe(2, room1);

        let (_, rooms) = registry.unregister_session(1).unwrap();
        assert_eq!(rooms.len(), 2);
        assert!(rooms.contains(&room1));
        assert!(rooms.contains(&room2));

        // Session 1 should be removed from room1
        let sessions: Vec<_> = registry.sessions_in_room(room1).collect();
        assert_eq!(sessions, vec![2]);

        // Room2 should have no subscribers (empty set cleaned up)
        assert_eq!(registry.room_session_count(room2), 0);
    }

    #[test]
    fn rooms_for_session() {
        let mut registry = ConnectionRegistry::new();
        let room1 = 0x1111_1111_1111_1111_1111_1111_1111_1111;
        let room2 = 0x2222_2222_2222_2222_2222_2222_2222_2222;

        registry.register_session(1, SessionInfo::new());
        registry.subscribe(1, room1);
        registry.subscribe(1, room2);

        let rooms: HashSet<_> = registry.rooms_for_session(1).collect();
        assert_eq!(rooms.len(), 2);
        assert!(rooms.contains(&room1));
        assert!(rooms.contains(&room2));
    }

    #[test]
    fn session_count() {
        let mut registry = ConnectionRegistry::new();

        assert_eq!(registry.session_count(), 0);

        registry.register_session(1, SessionInfo::new());
        assert_eq!(registry.session_count(), 1);

        registry.register_session(2, SessionInfo::new());
        assert_eq!(registry.session_count(), 2);

        registry.unregister_session(1);
        assert_eq!(registry.session_count(), 1);
    }

    #[test]
    fn update_session_info() {
        let mut registry = ConnectionRegistry::new();

        registry.register_session(1, SessionInfo::new());

        {
            let info = registry.sessions_mut(1).unwrap();
            info.authenticated = true;
            info.user_id = Some(42);
        }

        let info = registry.sessions(1).unwrap();
        assert!(info.authenticated);
        assert_eq!(info.user_id, Some(42));
    }
}
