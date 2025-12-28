//! Integration tests for client QUIC transport.
//!
//! These tests verify the real transport layer works correctly by connecting
//! actual QUIC clients to actual QUIC servers.

use std::time::Duration;

use lockframe_client::transport::{self, TransportConfig};
use lockframe_proto::{
    Frame, FrameHeader, Opcode,
    payloads::{Payload, session::Hello},
};
use lockframe_server::{Server, ServerRuntimeConfig};
use tokio::time::timeout;

/// Create a proper Hello frame with payload.
fn make_hello_frame() -> Frame {
    let hello = Hello { version: 1, capabilities: vec![], auth_token: None };
    let payload = Payload::Hello(hello);
    payload.into_frame(FrameHeader::new(Opcode::Hello)).unwrap()
}

/// Start a real server and return it along with its address.
async fn start_server() -> (Server, String) {
    let config = ServerRuntimeConfig {
        bind_address: "127.0.0.1:0".to_string(),
        cert_path: None,
        key_path: None,
        driver: Default::default(),
    };
    let server = Server::bind(config).await.unwrap();
    let addr = server.local_addr().unwrap().to_string();
    (server, addr)
}

#[tokio::test]
async fn client_connects_to_server() {
    let (server, addr) = start_server().await;

    // Spawn server to accept connections
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // This should succeed - client connects to server
    let result = transport::connect(&addr).await;

    assert!(result.is_ok(), "client should connect: {:?}", result.err());
}

#[tokio::test]
async fn client_connect_fails_for_invalid_address() {
    // No server running on this port - use short timeout since we expect failure
    let config = TransportConfig {
        connect_timeout: Duration::from_millis(500),
        ..TransportConfig::development()
    };
    let result = transport::connect_with_config("127.0.0.1:59999", config).await;

    assert!(result.is_err(), "should fail to connect to invalid address");
}

#[tokio::test]
async fn client_can_send_frame_to_server() {
    let (server, addr) = start_server().await;

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = transport::connect(&addr).await.unwrap();

    // Send a Hello frame with proper payload
    let frame = make_hello_frame();

    let result = client.to_server.send(frame).await;

    assert!(result.is_ok(), "should send frame: {:?}", result.err());
}

#[tokio::test]
async fn client_receives_hello_reply_from_server() {
    let (server, addr) = start_server().await;

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = transport::connect(&addr).await.unwrap();

    // Send a Hello frame with proper payload
    let frame = make_hello_frame();
    client.to_server.send(frame).await.unwrap();

    // Wait for HelloReply response
    let response = timeout(Duration::from_secs(5), client.from_server.recv()).await;

    assert!(response.is_ok(), "should receive response within timeout");
    let response = response.unwrap();
    assert!(response.is_some(), "should receive a frame");

    let frame = response.unwrap();
    assert_eq!(frame.header.opcode(), Opcode::HelloReply as u16, "should receive HelloReply");
}

#[tokio::test]
async fn client_ping_pong_after_handshake() {
    let (server, addr) = start_server().await;

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client = transport::connect(&addr).await.unwrap();

    // First, complete the handshake with proper Hello payload
    let hello_frame = make_hello_frame();
    client.to_server.send(hello_frame).await.unwrap();

    // Wait for HelloReply
    let response = timeout(Duration::from_secs(5), client.from_server.recv()).await;
    assert!(response.is_ok(), "should receive HelloReply within timeout");
    let response = response.unwrap().unwrap();
    assert_eq!(response.header.opcode(), Opcode::HelloReply as u16);

    // Now send Ping - should get Pong back
    let ping_header = FrameHeader::new(Opcode::Ping);
    let ping_frame = Frame::new(ping_header, Vec::new());
    client.to_server.send(ping_frame).await.unwrap();

    // Wait for Pong response
    let response = timeout(Duration::from_secs(5), client.from_server.recv()).await;

    assert!(response.is_ok(), "should receive Pong within timeout");
    let response = response.unwrap();
    assert!(response.is_some(), "should receive a frame");

    let frame = response.unwrap();
    assert_eq!(frame.header.opcode(), Opcode::Pong as u16, "should receive Pong");
}

#[tokio::test]
async fn client_stops_cleanly() {
    let (server, addr) = start_server().await;

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = transport::connect(&addr).await.unwrap();

    // Stop should not panic
    client.stop();

    // Small delay to allow cleanup
    tokio::time::sleep(Duration::from_millis(50)).await;
}
