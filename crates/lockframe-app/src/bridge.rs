//! Protocol-to-Application translation layer.
//!
//! The [`Bridge`] wraps the low-level [`lockframe_client::Client`] and adapts
//! it to the high-level application lifecycle.
//!
//! # Responsibilities
//!
//! - Converts high-level [`crate::AppAction`] into specific protocol frames and
//!   client operations.
//! - Accumulates outgoing [`lockframe_proto::Frame`] to be sent by the driver
//!   in the next I/O cycle.
//! - Interprets results from the client and converts them back into
//!   [`crate::AppEvent`]s to update the UI.
//! - Manages time ticks generically to support both real-time execution and
//!   deterministic simulation.

use lockframe_client::{Client, ClientAction, ClientError, ClientEvent, ClientIdentity};
use lockframe_core::env::Environment;
use lockframe_proto::{Frame, FrameHeader, Opcode, Payload, payloads::session::SyncRequest};

use crate::{AppAction, AppEvent};

/// Bridge between App and Client protocol logic.
///
/// Generic over Environment to support both production and simulation.
/// The Instant type is determined by the Environment's associated type.
pub struct Bridge<E: Environment> {
    client: Client<E>,
    outgoing: Vec<Frame>,
}

impl<E: Environment> Bridge<E> {
    /// Create a new Bridge with the given environment and sender ID.
    pub fn new(env: E, sender_id: u64) -> Self {
        let identity = ClientIdentity::new(sender_id);
        let client = Client::new(env, identity);
        Self { client, outgoing: Vec::new() }
    }

    /// Client's stable sender ID.
    pub fn sender_id(&self) -> u64 {
        self.client.sender_id()
    }

    /// Process an App action and return resulting App events.
    pub fn process_app_action(&mut self, action: AppAction) -> Vec<AppEvent> {
        match action {
            AppAction::CreateRoom { room_id } => {
                let result = self.client.handle(ClientEvent::CreateRoom { room_id });
                self.handle_client_result(result)
            },
            AppAction::SendMessage { room_id, content } => {
                let result = self
                    .client
                    .handle(ClientEvent::SendMessage { room_id, plaintext: content.clone() });
                let mut events = self.handle_client_result(result);

                if !events.iter().any(|e| matches!(e, AppEvent::Error { .. })) {
                    // Optimistically show own message as server won't echo it back and we can't
                    // decrypt own messages due to ratchet
                    events.push(AppEvent::MessageReceived {
                        room_id,
                        sender_id: self.client.sender_id(),
                        content,
                    });
                }
                events
            },
            AppAction::LeaveRoom { room_id } => {
                let result = self.client.handle(ClientEvent::LeaveRoom { room_id });
                self.handle_client_result(result)
            },
            AppAction::JoinRoom { room_id } => {
                let result = self.client.handle(ClientEvent::ExternalJoin { room_id });
                self.handle_client_result(result)
            },
            AppAction::PublishKeyPackage => {
                let result = self.client.handle(ClientEvent::PublishKeyPackage);
                self.handle_client_result(result)
            },
            AppAction::AddMember { room_id, user_id } => {
                let result =
                    self.client.handle(ClientEvent::FetchAndAddMember { room_id, user_id });
                self.handle_client_result(result)
            },
            AppAction::Render | AppAction::Quit | AppAction::Connect { .. } => vec![],
        }
    }

    /// Handle a frame from the server.
    pub fn handle_frame(&mut self, frame: Frame) -> Vec<AppEvent> {
        let result = self.client.handle(ClientEvent::FrameReceived(frame));
        self.handle_client_result(result)
    }

    /// Process a time tick.
    pub fn handle_tick(&mut self, now: E::Instant) -> Vec<AppEvent> {
        let result = self.client.handle(ClientEvent::Tick { now });
        self.handle_client_result(result)
    }

    /// Take pending outgoing frames.
    pub fn take_outgoing(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.outgoing)
    }

    fn handle_client_result(
        &mut self,
        result: Result<Vec<ClientAction>, ClientError>,
    ) -> Vec<AppEvent> {
        match result {
            Ok(actions) => self.process_client_actions(actions),
            Err(e) => vec![AppEvent::Error { message: e.to_string() }],
        }
    }

    fn process_client_actions(&mut self, actions: Vec<ClientAction>) -> Vec<AppEvent> {
        let mut events = Vec::new();

        for action in actions {
            match action {
                ClientAction::Send(frame) => {
                    self.outgoing.push(frame);
                },
                ClientAction::DeliverMessage { room_id, sender_id, plaintext, .. } => {
                    events.push(AppEvent::MessageReceived {
                        room_id,
                        sender_id,
                        content: plaintext,
                    });
                },
                ClientAction::RoomRemoved { room_id, .. } => {
                    events.push(AppEvent::RoomLeft { room_id });
                },
                ClientAction::PersistRoom(snapshot) => {
                    events.push(AppEvent::RoomJoined { room_id: snapshot.room_id });
                },
                ClientAction::RequestSync { from_epoch, .. } => {
                    let payload = SyncRequest { from_log_index: from_epoch, limit: 100 };
                    Payload::SyncRequest(payload)
                        .into_frame(FrameHeader::new(Opcode::SyncRequest))
                        .ok()
                        .map(|frame| {
                            self.outgoing.push(frame);
                        });
                },
                ClientAction::Log { .. } => {},
                ClientAction::MemberAdded { room_id, user_id } => {
                    events.push(AppEvent::MemberAdded { room_id, member_id: user_id });
                },
                ClientAction::KeyPackagePublished => {},
                ClientAction::KeyPackageNeeded { reason } => {
                    tracing::warn!(%reason, "KeyPackage needed, auto-republishing");
                    self.client
                        .handle(ClientEvent::PublishKeyPackage)
                        .ok()
                        .map(|actions| events.extend(self.process_client_actions(actions)));
                },
                ClientAction::RoomJoined { room_id, .. } => {
                    events.push(AppEvent::RoomJoined { room_id });
                    let payload = SyncRequest { from_log_index: 0, limit: 1000 };

                    Payload::SyncRequest(payload)
                        .into_frame(FrameHeader::new(Opcode::SyncRequest))
                        .ok()
                        .map(|mut frame| {
                            frame.header.set_room_id(room_id);
                            self.outgoing.push(frame);
                        });
                },
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use lockframe_core::env::Environment;

    use super::*;

    struct ImmediateFuture;

    impl Future for ImmediateFuture {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(())
        }
    }

    #[derive(Clone)]
    struct TestEnv;

    impl Environment for TestEnv {
        type Instant = std::time::Instant;
        fn now(&self) -> std::time::Instant {
            std::time::Instant::now()
        }

        fn sleep(&self, _duration: Duration) -> impl Future<Output = ()> + Send {
            ImmediateFuture
        }

        fn random_bytes(&self, buffer: &mut [u8]) {
            for (i, byte) in buffer.iter_mut().enumerate() {
                *byte = i as u8;
            }
        }
    }

    #[test]
    fn create_room_produces_room_joined() {
        let mut bridge: Bridge<TestEnv> = Bridge::new(TestEnv, 42);
        let events = bridge.process_app_action(AppAction::CreateRoom { room_id: 1 });
        assert!(events.iter().any(|e| matches!(e, AppEvent::RoomJoined { room_id: 1 })));
    }

    #[test]
    fn send_message_produces_outgoing_frame() {
        let mut bridge: Bridge<TestEnv> = Bridge::new(TestEnv, 42);
        let _ = bridge.process_app_action(AppAction::CreateRoom { room_id: 1 });
        let _ = bridge.take_outgoing();

        let _ = bridge
            .process_app_action(AppAction::SendMessage { room_id: 1, content: b"hello".to_vec() });

        assert!(!bridge.take_outgoing().is_empty());
    }

    #[test]
    fn send_to_unknown_room_produces_error() {
        let mut bridge: Bridge<TestEnv> = Bridge::new(TestEnv, 42);
        let events = bridge.process_app_action(AppAction::SendMessage {
            room_id: 999,
            content: b"hello".to_vec(),
        });
        assert!(events.iter().any(|e| matches!(e, AppEvent::Error { .. })));
    }
}
