//! Connection registry for session and room subscription tracking.
//!
//! The registry maintains bidirectional mappings: room → sessions (for
//! broadcast) and session → rooms (for cleanup on disconnect). This enables
//! O(1) lookups in both directions.
//!
//! Sessions must explicitly subscribe to rooms - no lazy room creation. When
//! you unregister a session, we automatically remove all its subscriptions.

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
/// - Get session ID for a user (for Welcome routing) - O(1) lookup
/// - Enforces one session per user for deterministic behavior
#[derive(Debug, Default)]
pub struct ConnectionRegistry {
    /// Session ID → session info
    sessions: HashMap<u64, SessionInfo>,
    /// Room ID → set of subscribed session IDs
    room_subscriptions: HashMap<u128, HashSet<u64>>,
    /// Session ID → set of subscribed room IDs
    session_rooms: HashMap<u64, HashSet<u128>>,
    /// User ID → session ID (reverse index). Enforces one session per user
    user_sessions: HashMap<u64, u64>,
}

impl ConnectionRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new session.
    ///
    /// Returns `false` if:
    /// - Session already exists, or
    /// - The session has a user_id and that user is already associated with
    ///   another session
    /// (enforces one session per user).
    pub fn register_session(&mut self, session_id: u64, info: SessionInfo) -> bool {
        if self.sessions.contains_key(&session_id) {
            return false;
        }

        // Check for user conflict if this session is authenticated
        if let Some(user_id) = info.user_id {
            if self.user_sessions.contains_key(&user_id) {
                return false; // User already has an active session
            }
            self.user_sessions.insert(user_id, session_id);
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

        // Clean up reverse index if this was an authenticated session
        if let Some(user_id) = info.user_id {
            self.user_sessions.remove(&user_id);
        }

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

    /// Session metadata. `None` if session doesn't exist.
    pub fn sessions(&self, session_id: u64) -> Option<&SessionInfo> {
        self.sessions.get(&session_id)
    }

    /// Mutable session metadata. `None` if session doesn't exist.
    pub fn sessions_mut(&mut self, session_id: u64) -> Option<&mut SessionInfo> {
        self.sessions.get_mut(&session_id)
    }

    /// Check if a session is registered.
    pub fn has_session(&self, session_id: u64) -> bool {
        self.sessions.contains_key(&session_id)
    }

    /// Update session info while maintaining the reverse index.
    ///
    /// This is the safe way to modify session authentication state.
    /// Returns `false` if session doesn't exist or if there's a user conflict.
    pub fn update_session_info(&mut self, session_id: u64, new_info: SessionInfo) -> bool {
        let old_info = match self.sessions.get(&session_id) {
            Some(info) => info.clone(),
            None => return false,
        };

        // Check for user conflict if new user_id is different
        if let Some(new_user_id) = new_info.user_id {
            if Some(new_user_id) != old_info.user_id {
                if self.user_sessions.contains_key(&new_user_id) {
                    return false; // New user already has an active session
                }
            }
        }

        // Remove old reverse index entry
        if let Some(old_user_id) = old_info.user_id {
            self.user_sessions.remove(&old_user_id);
        }

        // Add new reverse index entry
        if let Some(new_user_id) = new_info.user_id {
            self.user_sessions.insert(new_user_id, session_id);
        }

        self.sessions.insert(session_id, new_info);
        true
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

    /// All sessions subscribed to a room.
    pub fn sessions_in_room(&self, room_id: u128) -> impl Iterator<Item = u64> + '_ {
        self.room_subscriptions.get(&room_id).into_iter().flat_map(|s| s.iter().copied())
    }

    /// All rooms a session is subscribed to.
    pub fn rooms_for_session(&self, session_id: u64) -> impl Iterator<Item = u128> + '_ {
        self.session_rooms.get(&session_id).into_iter().flat_map(|r| r.iter().copied())
    }

    /// Find session ID for a given user ID.
    ///
    /// Used for routing Welcome frames to specific recipients.
    /// Returns `None` if no session is authenticated with this user ID.
    /// O(1) lookup using reverse index.
    pub fn session_id_for_user(&self, user_id: u64) -> Option<u64> {
        self.user_sessions.get(&user_id).copied()
    }

    /// Total number of registered sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Number of sessions subscribed to a room.
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

        registry.update_session_info(1, SessionInfo::authenticated(42));

        let info = registry.sessions(1).unwrap();
        assert!(info.authenticated);
        assert_eq!(info.user_id, Some(42));
    }

    #[test]
    fn session_id_for_user_finds_authenticated_session() {
        let mut registry = ConnectionRegistry::new();

        // Register sessions
        registry.register_session(200, SessionInfo::new());
        registry.register_session(300, SessionInfo::authenticated(99));

        // Authenticate session 200
        registry.update_session_info(200, SessionInfo::authenticated(42));

        // Find by user_id
        assert_eq!(registry.session_id_for_user(42), Some(200));
        assert_eq!(registry.session_id_for_user(99), Some(300));
        assert_eq!(registry.session_id_for_user(999), None);
    }

    #[test]
    fn one_session_per_user_enforcement() {
        let mut registry = ConnectionRegistry::new();

        // Register first session for user 42
        assert!(registry.register_session(1, SessionInfo::authenticated(42)));
        assert_eq!(registry.session_id_for_user(42), Some(1));

        // Try to register second session for same user - should fail
        assert!(!registry.register_session(2, SessionInfo::authenticated(42)));
        assert_eq!(registry.session_id_for_user(42), Some(1)); // Still points to first session

        // Register session for different user - should succeed
        assert!(registry.register_session(3, SessionInfo::authenticated(99)));
        assert_eq!(registry.session_id_for_user(99), Some(3));
    }

    #[test]
    fn update_session_info_handles_user_conflicts() {
        let mut registry = ConnectionRegistry::new();

        // Register two sessions with different users
        registry.register_session(1, SessionInfo::authenticated(42));
        registry.register_session(2, SessionInfo::authenticated(99));

        // Try to change session 2 to user 42 - should fail due to conflict
        assert!(!registry.update_session_info(2, SessionInfo::authenticated(42)));
        assert_eq!(registry.session_id_for_user(42), Some(1)); // Still points to session 1
        assert_eq!(registry.session_id_for_user(99), Some(2)); // Session 2 unchanged

        // Change session 2 to a new user - should succeed
        assert!(registry.update_session_info(2, SessionInfo::authenticated(100)));
        assert_eq!(registry.session_id_for_user(100), Some(2));
        assert_eq!(registry.session_id_for_user(99), None); // User 99 no longer has session
    }

    #[test]
    fn unregister_session_cleans_up_reverse_index() {
        let mut registry = ConnectionRegistry::new();

        registry.register_session(1, SessionInfo::authenticated(42));
        assert_eq!(registry.session_id_for_user(42), Some(1));

        // Unregister session
        let (info, rooms) = registry.unregister_session(1).unwrap();
        assert_eq!(info.user_id, Some(42));
        assert_eq!(registry.session_id_for_user(42), None); // Reverse index cleaned up
        assert!(rooms.is_empty());
    }
}
