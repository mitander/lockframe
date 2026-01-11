//! Simulation driver for App and Bridge testing.
//!
//! The SimDriver enables deterministic testing of the App+Bridge stack
//! by injecting events and capturing frames, without real network I/O.
//!
//! # Usage
//!
//! ```ignore
//! let env = SimEnv::new(42);
//! let mut driver = SimDriver::new(env.clone(), 1);
//!
//! // Inject a command
//! driver.inject_command("/create 100");
//! driver.process_pending();
//!
//! // Check state
//! assert!(driver.app().rooms().contains_key(&100));
//! ```

use std::{collections::VecDeque, ops::Sub, time::Duration};

use lockframe_app::{App, AppAction, AppEvent, Bridge, KeyInput};
use lockframe_core::env::Environment;
use lockframe_proto::Frame;

use crate::invariants::{ClientSnapshot, InvariantRegistry, RoomSnapshot, SystemSnapshot};

/// Simulation driver for App and Bridge.
///
/// Provides event injection and frame capture for deterministic testing.
/// Generic over Instant to support both real and virtual time.
pub struct SimDriver<E: Environment, I = std::time::Instant>
where
    I: Copy + Ord + Sub<Output = Duration>,
{
    app: App,
    bridge: Bridge<E, I>,
    pending_events: VecDeque<AppEvent>,
    outgoing_frames: Vec<Frame>,
    incoming_frames: VecDeque<Frame>,
    invariants: Option<InvariantRegistry>,
}

impl<E: Environment, I> SimDriver<E, I>
where
    I: Copy + Ord + Sub<Output = Duration>,
{
    /// Create a new SimDriver with the given environment and sender ID.
    pub fn new(env: E, sender_id: u64, server_addr: &str) -> Self {
        Self {
            app: App::new(server_addr.to_string()),
            bridge: Bridge::new(env, sender_id),
            pending_events: VecDeque::new(),
            outgoing_frames: Vec::new(),
            incoming_frames: VecDeque::new(),
            invariants: None,
        }
    }

    /// Enable invariant checking after each operation.
    pub fn with_invariants(mut self, registry: InvariantRegistry) -> Self {
        self.invariants = Some(registry);
        self
    }

    /// Inject a single key event.
    pub fn inject_key(&mut self, key: KeyInput) {
        self.pending_events.push_back(AppEvent::Key(key));
    }

    /// Inject a command string (e.g., "/create 100").
    ///
    /// Automatically adds each character as a key event followed by Enter.
    pub fn inject_command(&mut self, cmd: &str) {
        for c in cmd.chars() {
            self.inject_key(KeyInput::Char(c));
        }
        self.inject_key(KeyInput::Enter);
    }

    /// Inject a message to send (types text and presses Enter).
    pub fn inject_message(&mut self, text: &str) {
        for c in text.chars() {
            self.inject_key(KeyInput::Char(c));
        }
        self.inject_key(KeyInput::Enter);
    }

    /// Inject a frame from the "server".
    pub fn inject_frame(&mut self, frame: Frame) {
        self.incoming_frames.push_back(frame);
    }

    /// Inject a connection event (simulates successful connect).
    pub fn inject_connected(&mut self, session_id: u64, sender_id: u64) {
        self.pending_events.push_back(AppEvent::Connected { session_id, sender_id });
    }

    /// Process all pending events and frames.
    ///
    /// Returns all outgoing frames that were generated.
    pub fn process_pending(&mut self) -> Vec<Frame> {
        // Process pending input events
        while let Some(event) = self.pending_events.pop_front() {
            self.process_event(event);
        }

        // Process incoming frames
        while let Some(frame) = self.incoming_frames.pop_front() {
            let events = self.bridge.handle_frame(frame);
            for event in events {
                self.process_event(event);
            }
        }

        // Collect outgoing frames
        let frames = self.bridge.take_outgoing();
        self.outgoing_frames.extend(frames.clone());

        self.check_invariants("after process_pending");

        frames
    }

    /// Process a single event through App and Bridge.
    fn process_event(&mut self, event: AppEvent) {
        let actions = self.app.handle(event);
        self.check_invariants("after app.handle");

        for action in actions {
            match action {
                AppAction::Render | AppAction::Quit | AppAction::Connect { .. } => {
                    // UI actions - no bridge processing
                },
                _ => {
                    let events = self.bridge.process_app_action(action);
                    self.check_invariants("after bridge.process");

                    for event in events {
                        // Recursively process bridge-generated events
                        let nested_actions = self.app.handle(event);
                        self.check_invariants("after nested app.handle");

                        for nested_action in nested_actions {
                            if !matches!(
                                nested_action,
                                AppAction::Render | AppAction::Quit | AppAction::Connect { .. }
                            ) {
                                let _ = self.bridge.process_app_action(nested_action);
                            }
                        }
                    }
                },
            }
        }
    }

    /// Check invariants if enabled.
    fn check_invariants(&self, context: &str) {
        if let Some(ref registry) = self.invariants {
            let snapshot = self.snapshot();
            registry.assert_all(&snapshot, context);
        }
    }

    /// Take all accumulated outgoing frames.
    pub fn take_outgoing(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.outgoing_frames)
    }

    /// Access the App state.
    pub fn app(&self) -> &App {
        &self.app
    }

    /// Access the App state mutably.
    pub fn app_mut(&mut self) -> &mut App {
        &mut self.app
    }

    /// Access the Bridge.
    pub fn bridge(&self) -> &Bridge<E, I> {
        &self.bridge
    }

    /// Create a snapshot of current state for invariant checking.
    pub fn snapshot(&self) -> SystemSnapshot {
        let mut rooms = std::collections::HashMap::new();
        for (room_id, room_state) in self.app.rooms() {
            rooms.insert(
                *room_id,
                RoomSnapshot::with_epoch(0) // App doesn't expose epoch, use 0
                    .with_members(room_state.members.iter().copied())
                    .with_message_count(room_state.messages.len()),
            );
        }

        let client = ClientSnapshot {
            id: self.bridge.sender_id(),
            active_room: self.app.active_room(),
            rooms,
            epoch_history: std::collections::HashMap::new(),
        };

        SystemSnapshot::single(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimEnv;

    fn create_driver() -> SimDriver<SimEnv> {
        let env = SimEnv::with_seed(42);
        SimDriver::new(env, 1, "localhost:4433")
    }

    #[test]
    fn inject_command_creates_room() {
        let mut driver = create_driver();

        // Simulate connected state
        driver.inject_connected(1, 1);
        driver.process_pending();

        // Create a room
        driver.inject_command("/create 100");
        driver.process_pending();

        assert!(driver.app().rooms().contains_key(&100));
    }

    #[test]
    fn inject_message_after_room_created() {
        let mut driver = create_driver();

        driver.inject_connected(1, 1);
        driver.process_pending();

        driver.inject_command("/create 100");
        driver.process_pending();

        // Clear previous outgoing frames
        driver.take_outgoing();

        // Send a message
        driver.inject_message("hello world");
        let frames = driver.process_pending();

        // Should produce outgoing frame
        assert!(!frames.is_empty());
    }

    #[test]
    fn invariants_checked_during_processing() {
        let mut driver = create_driver().with_invariants(InvariantRegistry::standard());

        driver.inject_connected(1, 1);
        driver.process_pending();

        driver.inject_command("/create 100");
        // Should not panic - invariants hold
        driver.process_pending();
    }

    #[test]
    fn snapshot_captures_state() {
        let mut driver = create_driver();

        driver.inject_connected(1, 1);
        driver.process_pending();

        driver.inject_command("/create 100");
        driver.process_pending();

        let snapshot = driver.snapshot();
        assert_eq!(snapshot.clients.len(), 1);
        assert_eq!(snapshot.clients[0].id, 1);
        assert!(snapshot.clients[0].rooms.contains_key(&100));
    }
}
