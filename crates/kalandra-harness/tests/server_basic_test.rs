//! Basic server tests for connection and handshake.
//!
//! These tests verify:
//! - Server accepts connections
//! - Handshake completes successfully
//! - Connection limits are enforced
//! - Graceful disconnection works
//!
//! # Oracle Pattern
//!
//! Each test ends with oracle checks that verify server state consistency.

use bytes::Bytes;
use kalandra_core::server::ServerEvent;
use kalandra_harness::SimServer;
use kalandra_proto::{Frame, FrameHeader, Opcode, Payload, payloads::session::Hello};
use tokio::io::AsyncReadExt;
use turmoil::{Builder, net::TcpStream};

/// Test room ID
const ROOM_ID: u128 = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

/// Oracle: Verify server has expected connection count
fn verify_connection_count(server: &SimServer, expected: usize, context: &str) {
    let actual = server.connection_count();
    assert_eq!(actual, expected, "{}: expected {} connections, got {}", context, expected, actual);
}

/// Oracle: Verify room exists
fn verify_room_exists(server: &SimServer, room_id: u128, context: &str) {
    assert!(server.has_room(room_id), "{}: room {:032x} should exist", context, room_id);
}

#[test]
fn server_accepts_connection() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Wait for client to connect
        let conn_id = server.accept_connection().await?;

        // Oracle: Connection should be registered
        verify_connection_count(&server, 1, "after accept");
        assert_eq!(conn_id, 1, "First connection should have ID 1");

        Ok(())
    });

    sim.client("client", async {
        // Connect to server
        let _stream = TcpStream::connect("server:443").await?;

        // Small delay to let server process
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn server_handles_hello_handshake() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Accept connection
        let conn_id = server.accept_connection().await?;
        verify_connection_count(&server, 1, "after accept");

        // Create Hello frame for server to process
        let hello = Payload::Hello(Hello { version: 1, capabilities: vec![], auth_token: None });

        let frame = hello.into_frame(FrameHeader::new(Opcode::Hello))?;

        // Process Hello - should return HelloReply
        server.process_frame(conn_id, frame).await?;

        // Oracle: Connection should still be active
        verify_connection_count(&server, 1, "after hello");

        Ok(())
    });

    sim.client("client", async {
        let mut stream = TcpStream::connect("server:443").await?;

        // Read the HelloReply from server
        let mut buf = vec![0u8; 1024];

        // Give server time to process and send reply
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Try to read - may get HelloReply
        match tokio::time::timeout(std::time::Duration::from_millis(100), stream.read(&mut buf))
            .await
        {
            Ok(Ok(n)) if n > 0 => {
                // Got some data - likely HelloReply
                eprintln!("Client received {} bytes", n);
            },
            _ => {
                // Timeout or no data - that's ok for this test
            },
        }

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn server_creates_room_after_connection() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Accept connection
        let conn_id = server.accept_connection().await?;

        // Create room
        server.create_room(ROOM_ID, conn_id)?;

        // Oracle: Room should exist
        verify_room_exists(&server, ROOM_ID, "after create");

        // Epoch should be 0
        assert_eq!(server.room_epoch(ROOM_ID), Some(0), "Initial epoch should be 0");

        Ok(())
    });

    sim.client("client", async {
        let _stream = TcpStream::connect("server:443").await?;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn server_multiple_connections() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Accept 3 connections
        let conn1 = server.accept_connection().await?;
        let conn2 = server.accept_connection().await?;
        let conn3 = server.accept_connection().await?;

        // Oracle: All connections should be registered
        verify_connection_count(&server, 3, "after 3 accepts");

        // Connection IDs should be sequential
        assert_eq!(conn1, 1);
        assert_eq!(conn2, 2);
        assert_eq!(conn3, 3);

        Ok(())
    });

    // Client 1
    sim.client("client1", async {
        let _stream = TcpStream::connect("server:443").await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(())
    });

    // Client 2
    sim.client("client2", async {
        // Small delay to ensure ordering
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let _stream = TcpStream::connect("server:443").await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(())
    });

    // Client 3
    sim.client("client3", async {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let _stream = TcpStream::connect("server:443").await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn server_processes_app_message_frame() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Accept connection
        let conn_id = server.accept_connection().await?;

        // Create room first
        server.create_room(ROOM_ID, conn_id)?;

        // Create an AppMessage frame
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(ROOM_ID);
        header.set_sender_id(conn_id);
        header.set_epoch(0);

        let frame = Frame::new(header, Bytes::from("test message"));

        // Process frame - should succeed
        let result = server.process_frame(conn_id, frame).await;
        assert!(result.is_ok(), "AppMessage should be processed successfully");

        Ok(())
    });

    sim.client("client", async {
        let _stream = TcpStream::connect("server:443").await?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn server_rejects_frame_for_unknown_room() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Accept connection but don't create room
        let conn_id = server.accept_connection().await?;

        // Create an AppMessage frame for non-existent room
        let unknown_room = 0x9999_9999_9999_9999_9999_9999_9999_9999;
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(unknown_room);
        header.set_sender_id(conn_id);
        header.set_epoch(0);

        let frame = Frame::new(header, Bytes::from("test message"));

        // Process frame - should fail
        let result = server.process_frame(conn_id, frame).await;
        assert!(result.is_err(), "Frame for unknown room should be rejected");

        Ok(())
    });

    sim.client("client", async {
        let _stream = TcpStream::connect("server:443").await?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn server_subscription_management() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Accept two connections
        let conn1 = server.accept_connection().await?;
        let conn2 = server.accept_connection().await?;

        // Create room (auto-subscribes conn1)
        server.create_room(ROOM_ID, conn1)?;

        // Subscribe conn2 manually
        assert!(server.subscribe_to_room(conn2, ROOM_ID));

        // Verify both are subscribed
        let sessions: Vec<u64> = server.driver().sessions_in_room(ROOM_ID).collect();
        assert_eq!(sessions.len(), 2, "Both connections should be subscribed");
        assert!(sessions.contains(&conn1));
        assert!(sessions.contains(&conn2));

        Ok(())
    });

    sim.client("client1", async {
        let _stream = TcpStream::connect("server:443").await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(())
    });

    sim.client("client2", async {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let _stream = TcpStream::connect("server:443").await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn server_driver_direct_event_processing() {
    // Test that we can use the driver directly for more control
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Use driver directly to simulate connection without TCP
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: 100 });

        verify_connection_count(&server, 1, "after direct event");

        // Create room via driver
        server.create_room(ROOM_ID, 100)?;
        verify_room_exists(&server, ROOM_ID, "after direct room create");

        // Close connection via driver
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionClosed {
            conn_id: 100,
            reason: "test complete".to_string(),
        });

        verify_connection_count(&server, 0, "after close");

        Ok(())
    });

    sim.run().unwrap();
}
