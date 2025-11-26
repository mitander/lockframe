//! Connection lifecycle integration tests.
//!
//! Tests the full connection state machine over the simulated network:
//! - Handshake flow (Hello -> HelloReply)
//! - Heartbeat/keepalive
//! - Timeout detection
//! - Graceful shutdown

use sunder_core::{
    connection::{Connection, ConnectionConfig, ConnectionState},
    env::Environment,
    transport::Transport,
};
use sunder_harness::{SimEnv, SimTransport};
use sunder_proto::{
    Frame, FrameHeader, Opcode, Payload,
    payloads::session::{Goodbye, Hello, HelloReply},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Helper to convert any error to Box<dyn Error>
fn to_box_err<E: std::error::Error + 'static>(e: E) -> Box<dyn std::error::Error> {
    Box::new(e)
}

#[test]
fn connection_handshake_lifecycle() {
    let mut sim = turmoil::Builder::new().build();

    // Server: accept connection, receive Hello, send HelloReply
    sim.host("server", || async move {
        let env = SimEnv::new();
        let transport = SimTransport::bind("0.0.0.0:443").await?;
        let conn = transport.accept().await?;
        let (mut send, mut recv) = conn.into_split();

        // Read Hello frame
        let mut header_buf = [0u8; FrameHeader::SIZE];
        recv.read_exact(&mut header_buf).await?;
        let header = FrameHeader::from_bytes(&header_buf).map_err(to_box_err)?;

        assert_eq!(header.opcode_enum(), Some(Opcode::Hello));

        let payload_size = header.payload_size() as usize;
        let mut payload_buf = vec![0u8; payload_size];
        recv.read_exact(&mut payload_buf).await?;

        let frame = Frame::new(*header, payload_buf);
        let payload = Payload::from_frame(frame).map_err(to_box_err)?;

        // Verify Hello
        match payload {
            Payload::Hello(hello) => {
                assert_eq!(hello.version, 1);

                // Generate session ID
                let session_id = env.random_u64();

                // Send HelloReply
                let reply = Payload::HelloReply(HelloReply {
                    session_id,
                    capabilities: vec![],
                    challenge: None,
                });

                let reply_frame =
                    reply.into_frame(FrameHeader::new(Opcode::HelloReply)).map_err(to_box_err)?;
                let mut reply_buf = Vec::new();
                reply_frame.encode(&mut reply_buf).map_err(to_box_err)?;
                send.write_all(&reply_buf).await?;

                Ok(())
            },
            _ => Err(to_box_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected Hello",
            ))),
        }
    });

    // Client: connect, manage state machine, send Hello, receive HelloReply
    sim.client("client", async {
        let env = SimEnv::new();
        let transport = SimTransport::client();
        let conn = transport.connect_to_host("server:443").await?;
        let (mut send, mut recv) = conn.into_split();

        // Create connection state machine
        let now = env.now();
        let mut conn = Connection::new(now, ConnectionConfig::default());
        assert_eq!(conn.state(), ConnectionState::Init);

        // Send Hello
        let hello = Payload::Hello(Hello { version: 1, capabilities: vec![], auth_token: None });

        let hello_frame = hello.into_frame(FrameHeader::new(Opcode::Hello)).map_err(to_box_err)?;
        let mut hello_buf = Vec::new();
        hello_frame.encode(&mut hello_buf).map_err(to_box_err)?;
        send.write_all(&hello_buf).await?;

        // Update state machine
        let now = env.now();
        conn.send_hello(now).map_err(to_box_err)?;
        assert_eq!(conn.state(), ConnectionState::Pending);

        // Receive HelloReply
        let mut header_buf = [0u8; FrameHeader::SIZE];
        recv.read_exact(&mut header_buf).await?;
        let header = FrameHeader::from_bytes(&header_buf).map_err(to_box_err)?;

        assert_eq!(header.opcode_enum(), Some(Opcode::HelloReply));

        let payload_size = header.payload_size() as usize;
        let mut payload_buf = vec![0u8; payload_size];
        recv.read_exact(&mut payload_buf).await?;

        let frame = Frame::new(*header, payload_buf);

        let now = env.now();
        conn.handle_frame(&frame, now).map_err(to_box_err)?;
        assert_eq!(conn.state(), ConnectionState::Authenticated);
        assert!(conn.session_id().is_some());
        Ok(())
    });

    sim.run().expect("handshake should complete successfully");
}

#[test]
fn connection_graceful_shutdown() {
    let mut sim = turmoil::Builder::new().build();

    // Server: handle Goodbye
    sim.host("server", || async move {
        let transport = SimTransport::bind("0.0.0.0:443").await?;
        let conn = transport.accept().await?;
        let (mut send, mut recv) = conn.into_split();

        // Read Goodbye frame
        let mut header_buf = [0u8; FrameHeader::SIZE];
        recv.read_exact(&mut header_buf).await?;
        let header = FrameHeader::from_bytes(&header_buf).map_err(to_box_err)?;

        assert_eq!(header.opcode_enum(), Some(Opcode::Goodbye));

        let payload_size = header.payload_size() as usize;
        let mut payload_buf = vec![0u8; payload_size];
        recv.read_exact(&mut payload_buf).await?;

        let frame = Frame::new(*header, payload_buf);
        let payload = Payload::from_frame(frame).map_err(to_box_err)?;

        // Verify Goodbye
        match payload {
            Payload::Goodbye(goodbye) => {
                assert!(!goodbye.reason.is_empty());

                // Send Goodbye acknowledgment
                let reply = Payload::Goodbye(Goodbye { reason: "ack".to_string() });

                let reply_frame =
                    reply.into_frame(FrameHeader::new(Opcode::Goodbye)).map_err(to_box_err)?;
                let mut reply_buf = Vec::new();
                reply_frame.encode(&mut reply_buf).map_err(to_box_err)?;
                send.write_all(&reply_buf).await?;

                Ok(())
            },
            _ => Err(to_box_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected Goodbye",
            ))),
        }
    });

    // Client: send Goodbye
    sim.client("client", async {
        let env = SimEnv::new();
        let transport = SimTransport::client();
        let conn = transport.connect_to_host("server:443").await?;
        let (mut send, mut recv) = conn.into_split();

        let now = env.now();
        let mut conn = Connection::new(now, ConnectionConfig::default());

        // Send Goodbye
        let goodbye = Payload::Goodbye(Goodbye { reason: "client shutdown".to_string() });

        let goodbye_frame =
            goodbye.into_frame(FrameHeader::new(Opcode::Goodbye)).map_err(to_box_err)?;
        let mut goodbye_buf = Vec::new();
        goodbye_frame.encode(&mut goodbye_buf).map_err(to_box_err)?;
        send.write_all(&goodbye_buf).await?;

        // Update state
        conn.close();
        assert_eq!(conn.state(), ConnectionState::Closed);

        // Receive Goodbye ack
        let mut header_buf = [0u8; FrameHeader::SIZE];
        recv.read_exact(&mut header_buf).await?;
        let header = FrameHeader::from_bytes(&header_buf).map_err(to_box_err)?;
        assert_eq!(header.opcode_enum(), Some(Opcode::Goodbye));

        Ok(())
    });

    sim.run().expect("graceful shutdown should complete");
}
