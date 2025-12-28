//! In-process simulated server.
//!
//! Runs the ServerDriver in-process using channels for frame transport.
//! No network - frames flow through mpsc channels for deterministic testing
//! with a real terminal.

use lockframe_proto::Frame;
use lockframe_server::{
    DriverConfig, MemoryStorage, ServerAction, ServerDriver, ServerEvent, SystemEnv,
};
use tokio::sync::mpsc;

/// Handle to a running in-process server.
pub struct ServerHandle {
    /// Send frames to the server.
    pub to_server: mpsc::Sender<Frame>,
    /// Receive frames from the server.
    pub from_server: mpsc::Receiver<Frame>,
    /// Abort handle to stop the server task.
    abort_handle: tokio::task::AbortHandle,
}

impl ServerHandle {
    /// Stop the server.
    pub fn stop(&self) {
        self.abort_handle.abort();
    }
}

/// Spawn an in-process simulated server.
///
/// Returns a handle with channels for frame transport. The server runs as a
/// tokio task until dropped or stopped.
pub fn spawn_server(session_id: u64) -> ServerHandle {
    let (client_tx, mut server_rx) = mpsc::channel::<Frame>(32);
    let (server_tx, client_rx) = mpsc::channel::<Frame>(32);

    let handle = tokio::spawn(async move {
        let env = SystemEnv::new();
        let storage = MemoryStorage::new();
        let mut driver = ServerDriver::new(env, storage, DriverConfig::default());

        if let Err(e) = driver.process_event(ServerEvent::ConnectionAccepted { session_id }) {
            eprintln!("Server: connection accept failed: {e}");
            return;
        }

        loop {
            tokio::select! {
                Some(frame) = server_rx.recv() => {
                    let room_id = frame.header.room_id();
                    if room_id != 0 && !driver.has_room(room_id) {
                        // Auto-create room if it doesn't exist
                        if let Err(e) = driver.create_room(room_id, session_id) {
                            eprintln!("Server: room creation failed: {e}");
                        }
                    }

                    let result = driver.process_event(ServerEvent::FrameReceived {
                        session_id,
                        frame,
                    });

                    match result {
                        Ok(actions) => {
                            for action in actions {
                                if let Err(e) = execute_action(&server_tx, action, session_id).await {
                                    eprintln!("Server: action execution failed: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Server: frame processing failed: {e}");
                        }
                    }
                }
                else => break,
            }
        }
    });

    ServerHandle {
        to_server: client_tx,
        from_server: client_rx,
        abort_handle: handle.abort_handle(),
    }
}

/// Execute a server action.
async fn execute_action(
    tx: &mpsc::Sender<Frame>,
    action: ServerAction,
    our_session_id: u64,
) -> Result<(), String> {
    match action {
        ServerAction::SendToSession { session_id, frame } => {
            if session_id == our_session_id {
                tx.send(frame).await.map_err(|e| e.to_string())?;
            }
        },

        ServerAction::BroadcastToRoom { frame, exclude_session, .. } => {
            if exclude_session != Some(our_session_id) {
                // Single client, broadcast means send to us unless excluded
                tx.send(frame).await.map_err(|e| e.to_string())?;
            }
        },

        ServerAction::CloseConnection { .. }
        | ServerAction::PersistFrame { .. }
        | ServerAction::PersistMlsState { .. }
        | ServerAction::Log { .. } => {},
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use lockframe_proto::{FrameHeader, Opcode};

    use super::*;

    #[tokio::test]
    async fn server_can_receive_frame() {
        let handle = spawn_server(1);

        // Send a Hello frame
        let header = FrameHeader::new(Opcode::Hello);
        let frame = Frame::new(header, Vec::new());

        handle.to_server.send(frame).await.unwrap();

        // Give server time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Server should accept without panic - check if we can still send
        let header2 = FrameHeader::new(Opcode::Ping);
        let frame2 = Frame::new(header2, Vec::new());
        let result = handle.to_server.send(frame2).await;

        // Channel should still be open
        assert!(result.is_ok());

        handle.stop();
    }
}
