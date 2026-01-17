//! Integration tests for client QUIC transport.
//!
//! These tests verify the real transport layer works correctly by connecting
//! actual QUIC clients to actual QUIC servers.

use std::time::Duration;

use lockframe_client::transport::{self, ConnectedClient, TransportConfig};
use lockframe_proto::{
    Frame, FrameHeader, Opcode,
    payloads::{Payload, session::Hello},
};
use lockframe_server::{Server, ServerRuntimeConfig};
use tokio::time::timeout;

/// Create a proper Hello frame with payload.
fn make_hello_frame() -> Frame {
    let hello = Hello { version: 1, capabilities: vec![], sender_id: None, auth_token: None };
    let payload = Payload::Hello(hello);
    payload.into_frame(FrameHeader::new(Opcode::Hello)).unwrap()
}

/// Start a real server, spawn its run loop, and return the address.
async fn start_server() -> String {
    let config = ServerRuntimeConfig {
        bind_address: "127.0.0.1:0".to_string(),
        cert_path: None,
        key_path: None,
        driver: Default::default(),
    };
    let server = Server::bind(config).await.unwrap();
    let addr = server.local_addr().unwrap().to_string();

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    addr
}

/// Connect to server with retry. Avoids timing-dependent sleeps.
async fn connect_with_retry(addr: &str) -> ConnectedClient {
    let config = TransportConfig {
        connect_timeout: Duration::from_millis(100),
        ..TransportConfig::development()
    };

    for attempt in 0..20 {
        match transport::connect_with_config(addr, config.clone()).await {
            Ok(handle) => return handle,
            Err(_) if attempt < 19 => {
                tokio::task::yield_now().await;
            },
            Err(e) => panic!("failed to connect after 20 attempts: {e}"),
        }
    }
    unreachable!()
}

#[tokio::test]
async fn client_connects_to_server() {
    let addr = start_server().await;
    let _client = connect_with_retry(&addr).await;
}

#[tokio::test]
async fn client_connect_fails_for_invalid_address() {
    let config = TransportConfig {
        connect_timeout: Duration::from_millis(500),
        ..TransportConfig::development()
    };
    let result = transport::connect_with_config("127.0.0.1:59999", config).await;

    assert!(result.is_err(), "should fail to connect to invalid address");
}

#[tokio::test]
async fn client_can_send_frame_to_server() {
    let addr = start_server().await;
    let client = connect_with_retry(&addr).await;

    let frame = make_hello_frame();
    let result = client.to_server.send(frame).await;

    assert!(result.is_ok(), "should send frame: {:?}", result.err());
}

#[tokio::test]
async fn client_receives_hello_reply_from_server() {
    let addr = start_server().await;
    let mut client = connect_with_retry(&addr).await;

    let frame = make_hello_frame();
    client.to_server.send(frame).await.unwrap();

    let response = timeout(Duration::from_secs(5), client.from_server.recv()).await;

    assert!(response.is_ok(), "should receive response within timeout");
    let response = response.unwrap();
    assert!(response.is_some(), "should receive a frame");

    let frame = response.unwrap();
    assert_eq!(frame.header.opcode(), Opcode::HelloReply as u16, "should receive HelloReply");
}

#[tokio::test]
async fn client_ping_pong_after_handshake() {
    let addr = start_server().await;
    let mut client = connect_with_retry(&addr).await;

    let hello_frame = make_hello_frame();
    client.to_server.send(hello_frame).await.unwrap();

    let response = timeout(Duration::from_secs(5), client.from_server.recv()).await;
    assert!(response.is_ok(), "should receive HelloReply within timeout");
    let response = response.unwrap().unwrap();
    assert_eq!(response.header.opcode(), Opcode::HelloReply as u16);

    let ping_header = FrameHeader::new(Opcode::Ping);
    let ping_frame = Frame::new(ping_header, Vec::new());
    client.to_server.send(ping_frame).await.unwrap();

    let response = timeout(Duration::from_secs(5), client.from_server.recv()).await;
    assert!(response.is_ok(), "should receive Pong within timeout");

    let response = response.unwrap();
    assert!(response.is_some(), "should receive a frame");

    let frame = response.unwrap();
    assert_eq!(frame.header.opcode(), Opcode::Pong as u16, "should receive Pong");
}

#[tokio::test]
async fn client_stops_cleanly() {
    let addr = start_server().await;
    let client = connect_with_retry(&addr).await;

    // Stop should not panic
    client.stop();
}
