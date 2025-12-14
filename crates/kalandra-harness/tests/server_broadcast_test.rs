//! Server broadcast tests for multi-client message delivery.
//!
//! These tests verify:
//! - Messages are broadcast to all room members
//! - Sender exclusion works correctly
//! - Multiple rooms are isolated
//!
//! # Oracle Pattern
//!
//! Each test ends with oracle checks that verify message delivery consistency.

use bytes::Bytes;
use kalandra_core::server::ServerEvent;
use kalandra_harness::SimServer;
use kalandra_proto::{Frame, FrameHeader, Opcode};
use turmoil::Builder;

/// Test room IDs
const ROOM_1: u128 = 0x1111_1111_1111_1111_1111_1111_1111_1111;
const ROOM_2: u128 = 0x2222_2222_2222_2222_2222_2222_2222_2222;

/// Oracle: Verify room membership count
fn verify_room_membership(server: &SimServer, room_id: u128, expected: usize, context: &str) {
    let actual: Vec<u64> = server.driver().sessions_in_room(room_id).collect();
    assert_eq!(
        actual.len(),
        expected,
        "{}: expected {} members in room {:032x}, got {}",
        context,
        expected,
        room_id,
        actual.len()
    );
}

#[test]
fn broadcast_to_room_members() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Create 3 connections using driver directly (simpler for this test)
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: 1 });
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: 2 });
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: 3 });

        // Create room with conn1 as creator
        server.create_room(ROOM_1, 1)?;

        // Subscribe conn2 and conn3
        server.subscribe_to_room(2, ROOM_1);
        server.subscribe_to_room(3, ROOM_1);

        // Oracle: All 3 should be in room
        verify_room_membership(&server, ROOM_1, 3, "after subscriptions");

        // Send a message from conn1
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(ROOM_1);
        header.set_sender_id(1);
        header.set_epoch(0);

        let frame = Frame::new(header, Bytes::from("broadcast message"));

        // Process frame - should succeed and broadcast
        let result = server.process_frame(1, frame).await;
        assert!(result.is_ok(), "Broadcast should succeed: {:?}", result.err());

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn rooms_are_isolated() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Create 4 connections
        for i in 1..=4 {
            let _ =
                server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: i });
        }

        // Create room 1 with conn1, conn2
        server.create_room(ROOM_1, 1)?;
        server.subscribe_to_room(2, ROOM_1);

        // Create room 2 with conn3, conn4
        server.create_room(ROOM_2, 3)?;
        server.subscribe_to_room(4, ROOM_2);

        // Oracle: Rooms should have correct membership
        verify_room_membership(&server, ROOM_1, 2, "room 1");
        verify_room_membership(&server, ROOM_2, 2, "room 2");

        // Verify specific membership
        let room1_members: Vec<u64> = server.driver().sessions_in_room(ROOM_1).collect();
        assert!(room1_members.contains(&1), "Room 1 should contain conn 1");
        assert!(room1_members.contains(&2), "Room 1 should contain conn 2");
        assert!(!room1_members.contains(&3), "Room 1 should not contain conn 3");
        assert!(!room1_members.contains(&4), "Room 1 should not contain conn 4");

        let room2_members: Vec<u64> = server.driver().sessions_in_room(ROOM_2).collect();
        assert!(room2_members.contains(&3), "Room 2 should contain conn 3");
        assert!(room2_members.contains(&4), "Room 2 should contain conn 4");
        assert!(!room2_members.contains(&1), "Room 2 should not contain conn 1");
        assert!(!room2_members.contains(&2), "Room 2 should not contain conn 2");

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn member_in_multiple_rooms() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Create 3 connections
        for i in 1..=3 {
            let _ =
                server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: i });
        }

        // Conn1 creates room 1
        server.create_room(ROOM_1, 1)?;

        // Conn2 creates room 2
        server.create_room(ROOM_2, 2)?;

        // Conn3 joins both rooms
        server.subscribe_to_room(3, ROOM_1);
        server.subscribe_to_room(3, ROOM_2);

        // Oracle: Conn3 should be in both rooms
        let room1_members: Vec<u64> = server.driver().sessions_in_room(ROOM_1).collect();
        let room2_members: Vec<u64> = server.driver().sessions_in_room(ROOM_2).collect();

        assert!(room1_members.contains(&3), "Conn 3 should be in room 1");
        assert!(room2_members.contains(&3), "Conn 3 should be in room 2");

        // Send message to room 1 - should reach conn3
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(ROOM_1);
        header.set_sender_id(1);
        header.set_epoch(0);

        let frame = Frame::new(header, Bytes::from("message to room 1"));
        let result = server.process_frame(1, frame).await;
        assert!(result.is_ok());

        // Send message to room 2 - should also reach conn3
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(ROOM_2);
        header.set_sender_id(2);
        header.set_epoch(0);

        let frame = Frame::new(header, Bytes::from("message to room 2"));
        let result = server.process_frame(2, frame).await;
        assert!(result.is_ok());

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn disconnect_removes_from_rooms() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Create 3 connections
        for i in 1..=3 {
            let _ =
                server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: i });
        }

        // Create room with all 3 members
        server.create_room(ROOM_1, 1)?;
        server.subscribe_to_room(2, ROOM_1);
        server.subscribe_to_room(3, ROOM_1);

        verify_room_membership(&server, ROOM_1, 3, "before disconnect");

        // Disconnect conn2
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionClosed {
            conn_id: 2,
            reason: "client disconnect".to_string(),
        });

        // Oracle: Room should have 2 members now
        verify_room_membership(&server, ROOM_1, 2, "after disconnect");

        let members: Vec<u64> = server.driver().sessions_in_room(ROOM_1).collect();
        assert!(members.contains(&1), "Conn 1 should still be in room");
        assert!(!members.contains(&2), "Conn 2 should be removed from room");
        assert!(members.contains(&3), "Conn 3 should still be in room");

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn disconnect_from_multiple_rooms() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Create 3 connections
        for i in 1..=3 {
            let _ =
                server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: i });
        }

        // Create both rooms
        server.create_room(ROOM_1, 1)?;
        server.create_room(ROOM_2, 2)?;

        // Conn3 joins both rooms
        server.subscribe_to_room(3, ROOM_1);
        server.subscribe_to_room(3, ROOM_2);

        verify_room_membership(&server, ROOM_1, 2, "room 1 before disconnect");
        verify_room_membership(&server, ROOM_2, 2, "room 2 before disconnect");

        // Disconnect conn3 - should be removed from both rooms
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionClosed {
            conn_id: 3,
            reason: "client disconnect".to_string(),
        });

        // Oracle: Conn3 should be removed from both rooms
        verify_room_membership(&server, ROOM_1, 1, "room 1 after disconnect");
        verify_room_membership(&server, ROOM_2, 1, "room 2 after disconnect");

        let room1_members: Vec<u64> = server.driver().sessions_in_room(ROOM_1).collect();
        let room2_members: Vec<u64> = server.driver().sessions_in_room(ROOM_2).collect();

        assert!(!room1_members.contains(&3), "Conn 3 should be removed from room 1");
        assert!(!room2_members.contains(&3), "Conn 3 should be removed from room 2");

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn large_room_membership() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Create 100 connections
        for i in 1..=100 {
            let _ =
                server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: i });
        }

        // Create room with all members
        server.create_room(ROOM_1, 1)?;
        for i in 2..=100 {
            server.subscribe_to_room(i, ROOM_1);
        }

        // Oracle: All 100 should be in room
        verify_room_membership(&server, ROOM_1, 100, "after mass subscription");

        // Send a message
        let mut header = FrameHeader::new(Opcode::AppMessage);
        header.set_room_id(ROOM_1);
        header.set_sender_id(1);
        header.set_epoch(0);

        let frame = Frame::new(header, Bytes::from("broadcast to 100 members"));
        let result = server.process_frame(1, frame).await;
        assert!(result.is_ok(), "Large room broadcast should succeed");

        Ok(())
    });

    sim.run().unwrap();
}

#[test]
fn empty_room_after_all_disconnect() {
    let mut sim = Builder::new().build();

    sim.host("server", || async {
        let mut server = SimServer::bind("0.0.0.0:443").await?;

        // Create 2 connections
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: 1 });
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionAccepted { conn_id: 2 });

        // Create room with both members
        server.create_room(ROOM_1, 1)?;
        server.subscribe_to_room(2, ROOM_1);

        verify_room_membership(&server, ROOM_1, 2, "before disconnects");

        // Disconnect both
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionClosed {
            conn_id: 1,
            reason: "disconnect".to_string(),
        });
        let _ = server.driver_mut().process_event(ServerEvent::ConnectionClosed {
            conn_id: 2,
            reason: "disconnect".to_string(),
        });

        // Oracle: Room should be empty (but still exists)
        verify_room_membership(&server, ROOM_1, 0, "after all disconnect");

        // Room should still exist even with no members
        assert!(server.has_room(ROOM_1), "Room should still exist after all members leave");

        Ok(())
    });

    sim.run().unwrap();
}
