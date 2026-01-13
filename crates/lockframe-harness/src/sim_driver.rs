//! Simulation driver implementing the Driver trait.
//!
//! SimDriver provides the same interface as TerminalDriver but for
//! deterministic testing. It implements [`Driver`] so the same
//! [`lockframe_app::Runtime`] orchestration code runs in both production and
//! simulation.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use lockframe_app::{App, AppEvent, Driver, KeyInput};
use lockframe_proto::Frame;

use crate::invariants::{ClientSnapshot, InvariantRegistry, RoomSnapshot, SystemSnapshot};

/// Error type for simulation driver.
#[derive(Debug, Clone)]
pub struct SimDriverError(pub String);

impl std::fmt::Display for SimDriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SimDriverError: {}", self.0)
    }
}

impl std::error::Error for SimDriverError {}

/// Shared state for event injection.
///
/// This allows injection from outside async contexts.
#[derive(Default)]
struct SharedState {
    pending_events: VecDeque<AppEvent>,
    incoming_frames: VecDeque<Frame>,
    outgoing_frames: Vec<Frame>,
    connected: bool,
}

/// Simulation driver for deterministic testing.
///
/// Implements [`Driver`] trait so the same [`lockframe_app::Runtime`]
/// orchestration code runs in both production TUI and simulation tests.
pub struct SimDriver {
    state: Arc<Mutex<SharedState>>,
    invariants: Option<InvariantRegistry>,
}

impl Default for SimDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl SimDriver {
    /// Create a new simulation driver.
    pub fn new() -> Self {
        Self { state: Arc::new(Mutex::new(SharedState::default())), invariants: None }
    }

    /// Enable invariant checking.
    pub fn with_invariants(mut self, registry: InvariantRegistry) -> Self {
        self.invariants = Some(registry);
        self
    }

    /// Inject a single key event.
    pub fn inject_key(&self, key: KeyInput) {
        let mut state = self.state.lock().unwrap();
        state.pending_events.push_back(AppEvent::Key(key));
    }

    /// Inject a command string
    pub fn inject_command(&self, cmd: &str) {
        for c in cmd.chars() {
            self.inject_key(KeyInput::Char(c));
        }
        self.inject_key(KeyInput::Enter);
    }

    /// Inject a message to send.
    pub fn inject_message(&self, text: &str) {
        for c in text.chars() {
            self.inject_key(KeyInput::Char(c));
        }
        self.inject_key(KeyInput::Enter);
    }

    /// Inject a frame from the server.
    pub fn inject_frame(&self, frame: Frame) {
        let mut state = self.state.lock().unwrap();
        state.incoming_frames.push_back(frame);
    }

    /// Inject a tick event.
    pub fn inject_tick(&self) {
        let mut state = self.state.lock().unwrap();
        state.pending_events.push_back(AppEvent::Tick);
    }

    /// Take all captured outgoing frames.
    pub fn take_outgoing(&self) -> Vec<Frame> {
        let mut state = self.state.lock().unwrap();
        std::mem::take(&mut state.outgoing_frames)
    }

    /// Check if there are pending events to process.
    pub fn has_pending(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.pending_events.is_empty() || !state.incoming_frames.is_empty()
    }

    /// Create a snapshot from App state for invariant checking.
    pub fn snapshot_from_app(&self, app: &App) -> SystemSnapshot {
        let mut rooms = HashMap::new();
        for (room_id, room_state) in app.rooms() {
            rooms.insert(
                *room_id,
                RoomSnapshot::with_epoch(0)
                    .with_members(room_state.members.iter().copied())
                    .with_message_count(room_state.messages.len()),
            );
        }

        let client = ClientSnapshot {
            id: 0, // Caller sets this
            active_room: app.active_room(),
            rooms,
            epoch_history: HashMap::new(),
        };

        SystemSnapshot::single(client)
    }

    /// Check invariants against App state.
    pub fn check_invariants(&self, app: &App, context: &str) {
        if let Some(ref registry) = self.invariants {
            let snapshot = self.snapshot_from_app(app);
            registry.assert_all(&snapshot, context);
        }
    }
}

impl Driver for SimDriver {
    type Error = SimDriverError;
    type Instant = std::time::Instant;

    async fn poll_event(&mut self) -> Result<Option<AppEvent>, Self::Error> {
        let mut state = self.state.lock().unwrap();

        if let Some(event) = state.pending_events.pop_front() {
            return Ok(Some(event));
        }

        Ok(None)
    }

    async fn send_frame(&mut self, frame: Frame) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.outgoing_frames.push(frame);
        Ok(())
    }

    async fn recv_frame(&mut self) -> Option<Frame> {
        let mut state = self.state.lock().unwrap();
        state.incoming_frames.pop_front()
    }

    async fn connect(&mut self, _addr: &str) -> Result<(), Self::Error> {
        let mut state = self.state.lock().unwrap();
        state.connected = true;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.connected
    }

    fn now(&self) -> Self::Instant {
        std::time::Instant::now()
    }

    fn render(&mut self, _app: &App) -> Result<(), Self::Error> {
        Ok(())
    }

    fn stop(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_command_queues_events() {
        let driver = SimDriver::new();
        driver.inject_command("/create 100");

        assert!(driver.has_pending());
    }

    #[test]
    fn inject_frame_queues_frame() {
        let driver = SimDriver::new();
        let frame = Frame::new(
            lockframe_proto::FrameHeader::new(lockframe_proto::Opcode::Ping),
            Vec::new(),
        );
        driver.inject_frame(frame);

        assert!(driver.has_pending());
    }

    #[tokio::test]
    async fn poll_event_returns_injected() {
        let mut driver = SimDriver::new();
        driver.inject_key(KeyInput::Char('a'));

        let event = driver.poll_event().await.unwrap();
        assert!(matches!(event, Some(AppEvent::Key(KeyInput::Char('a')))));
    }

    #[tokio::test]
    async fn send_frame_captures() {
        let mut driver = SimDriver::new();
        let frame = Frame::new(
            lockframe_proto::FrameHeader::new(lockframe_proto::Opcode::Ping),
            Vec::new(),
        );

        driver.send_frame(frame).await.unwrap();

        let captured = driver.take_outgoing();
        assert_eq!(captured.len(), 1);
    }
}
