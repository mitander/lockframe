//! Bridge between App and Client.
//!
//! Translates between App actions/events and Client events/actions, keeping
//! the UI layer decoupled from protocol details.

use lockframe_client::{Client, ClientAction, ClientEvent, ClientIdentity};
use lockframe_core::env::Environment;
use lockframe_proto::{Frame, FrameHeader, Opcode, Payload, payloads::session::SyncRequest};

use crate::app::{AppAction, AppEvent};

/// Bridge between App UI and Client protocol logic.
///
/// Holds the Client state machine and buffers outgoing frames for the
/// transport layer to send.
pub struct Bridge<E: Environment> {
    client: Client<E>,
    /// Frames pending transmission to server.
    outgoing: Vec<Frame>,
}

impl<E: Environment> Bridge<E> {
    /// Create a new bridge with the given client.
    pub fn new(env: E, sender_id: u64) -> Self {
        let identity = ClientIdentity::new(sender_id);
        let client = Client::new(env, identity);
        Self { client, outgoing: Vec::new() }
    }

    /// Client's sender ID.
    pub fn sender_id(&self) -> u64 {
        self.client.sender_id()
    }

    /// Process an App action and return resulting App events.
    ///
    /// Translates UI-level actions into protocol operations, executes them
    /// on the Client, and translates the results back to UI events.
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

                // Optimistically show own message immediately (server won't echo it back,
                // and even if it did, we can't decrypt our own message due to ratchet advance)
                if !events.iter().any(|e| matches!(e, AppEvent::Error { .. })) {
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

    /// Handle a frame received from the server.
    pub fn handle_frame(&mut self, frame: Frame) -> Vec<AppEvent> {
        let result = self.client.handle(ClientEvent::FrameReceived(frame));
        self.handle_client_result(result)
    }

    /// Process a time tick.
    pub fn handle_tick(&mut self, now: std::time::Instant) -> Vec<AppEvent> {
        let result = self.client.handle(ClientEvent::Tick { now });
        self.handle_client_result(result)
    }

    /// Take all pending outgoing frames.
    pub fn take_outgoing(&mut self) -> Vec<Frame> {
        std::mem::take(&mut self.outgoing)
    }

    /// Convert Client result to App events, handling actions and errors.
    fn handle_client_result(
        &mut self,
        result: Result<Vec<ClientAction>, lockframe_client::ClientError>,
    ) -> Vec<AppEvent> {
        match result {
            Ok(actions) => self.process_client_actions(actions),
            Err(e) => vec![AppEvent::Error { message: e.to_string() }],
        }
    }

    /// Convert Client actions to App events.
    fn process_client_actions(&mut self, actions: Vec<ClientAction>) -> Vec<AppEvent> {
        let mut events = Vec::new();

        for action in actions {
            match action {
                ClientAction::Send(frame) => {
                    // Check if this is a room creation (first frame sent after CreateRoom)
                    // by looking for the PersistRoom action in the same batch
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
                    // from_epoch maps to from_log_index: epochs are a subset of
                    // sequenced frames, so from_epoch is a valid lower bound.
                    let payload = SyncRequest { from_log_index: from_epoch, limit: 100 };
                    match Payload::SyncRequest(payload)
                        .into_frame(FrameHeader::new(Opcode::SyncRequest))
                    {
                        Ok(frame) => self.outgoing.push(frame),
                        Err(e) => {
                            tracing::error!(from_epoch, error = %e, "Failed to create SyncRequest");
                        },
                    }
                },

                ClientAction::Log { .. } => {
                    // Handled internally, no UI event needed
                },

                ClientAction::MemberAdded { room_id, user_id } => {
                    events.push(AppEvent::MemberAdded { room_id, member_id: user_id });
                },

                ClientAction::KeyPackagePublished => {
                    // KeyPackage published successfully, no UI event needed
                },

                ClientAction::KeyPackageNeeded { reason } => {
                    tracing::warn!(%reason, "KeyPackage needed, auto-republishing");

                    match self.client.handle(ClientEvent::PublishKeyPackage) {
                        Ok(actions) => {
                            let republish_events = self.process_client_actions(actions);
                            events.extend(republish_events);
                        },
                        Err(e) => {
                            events.push(AppEvent::Error {
                                message: format!("Failed to republish KeyPackage: {}", e),
                            });
                        },
                    }
                },

                ClientAction::RoomJoined { room_id, epoch } => {
                    tracing::info!(%room_id, %epoch, "Joined room via external commit");
                    events.push(AppEvent::RoomJoined { room_id });
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
    fn create_room_produces_room_joined_event() {
        let mut bridge = Bridge::new(TestEnv, 42);

        let events = bridge.process_app_action(AppAction::CreateRoom { room_id: 1 });

        assert!(events.iter().any(|e| matches!(e, AppEvent::RoomJoined { room_id: 1 })));
    }

    #[test]
    fn send_message_produces_outgoing_frame() {
        let mut bridge = Bridge::new(TestEnv, 42);

        // Create a room first
        let _ = bridge.process_app_action(AppAction::CreateRoom { room_id: 1 });
        let _ = bridge.take_outgoing(); // Clear any initial frames

        // Sending a message should produce an outgoing frame
        let _ = bridge
            .process_app_action(AppAction::SendMessage { room_id: 1, content: b"hello".to_vec() });

        let frames = bridge.take_outgoing();
        assert!(!frames.is_empty());
    }

    #[test]
    fn send_message_to_unknown_room_produces_error() {
        let mut bridge = Bridge::new(TestEnv, 42);

        let events = bridge.process_app_action(AppAction::SendMessage {
            room_id: 999,
            content: b"hello".to_vec(),
        });

        assert!(events.iter().any(|e| matches!(e, AppEvent::Error { .. })));
    }

    #[test]
    fn leave_room_produces_room_left_event() {
        let mut bridge = Bridge::new(TestEnv, 42);

        // First create the room
        let _ = bridge.process_app_action(AppAction::CreateRoom { room_id: 1 });

        // Then leave it
        let events = bridge.process_app_action(AppAction::LeaveRoom { room_id: 1 });

        assert!(events.iter().any(|e| matches!(e, AppEvent::RoomLeft { room_id: 1 })));
    }

    #[test]
    fn welcome_without_keypackage_triggers_auto_republish() {
        use lockframe_proto::{Frame, FrameHeader, Opcode};

        let mut bridge = Bridge::new(TestEnv, 42);

        // Receive a Welcome without having published a KeyPackage
        let room_id = 0x1234_u128;
        let mut header = FrameHeader::new(Opcode::Welcome);
        header.set_room_id(room_id);
        let frame = Frame::new(header, vec![1, 2, 3, 4]);

        // Clear any existing outgoing frames
        let _ = bridge.take_outgoing();

        // Process the Welcome - should trigger auto-republish
        let _events = bridge.handle_frame(frame);

        // Should have generated a new KeyPackage publish frame
        let frames = bridge.take_outgoing();
        assert!(
            frames.iter().any(|f| f.header.opcode_enum() == Some(Opcode::KeyPackagePublish)),
            "Expected KeyPackagePublish frame after failed Welcome, got: {:?}",
            frames.iter().map(|f| f.header.opcode_enum()).collect::<Vec<_>>()
        );
    }
}
