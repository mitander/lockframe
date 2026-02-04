//! Network simulation tests using turmoil.
//!
//! These tests verify that turmoil's TCP simulation works correctly.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use turmoil::net::{TcpListener, TcpStream};

#[test]
fn basic_tcp_echo_works() {
    let mut sim = turmoil::Builder::new().build();

    sim.host("server", || async {
        let listener = TcpListener::bind("0.0.0.0:443").await?;
        let (mut stream, _) = listener.accept().await?;

        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await?;
        stream.write_all(&buf[..n]).await?;

        Ok(())
    });

    sim.client("client", async {
        let mut stream = TcpStream::connect("server:443").await?;

        stream.write_all(b"hello").await?;

        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await?;

        assert_eq!(&buf[..n], b"hello");
        Ok(())
    });

    sim.run().expect("simulation failed");
}

#[test]
fn multiple_clients_connect() {
    let mut sim = turmoil::Builder::new().build();

    sim.host("server", || async {
        let listener = TcpListener::bind("0.0.0.0:443").await?;

        // Accept 3 connections
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await?;

            // Echo back
            let mut buf = [0u8; 32];
            let n = stream.read(&mut buf).await?;
            stream.write_all(&buf[..n]).await?;
        }

        Ok(())
    });

    for i in 0..3 {
        let client_name = format!("client{i}");
        let msg = format!("msg{i}");
        sim.client(client_name, async move {
            let mut stream = TcpStream::connect("server:443").await?;

            stream.write_all(msg.as_bytes()).await?;

            let mut buf = [0u8; 32];
            let n = stream.read(&mut buf).await?;
            assert_eq!(&buf[..n], msg.as_bytes());

            Ok(())
        });
    }

    sim.run().expect("simulation failed");
}

#[test]
fn bidirectional_communication() {
    let mut sim = turmoil::Builder::new().build();

    sim.host("server", || async {
        let listener = TcpListener::bind("0.0.0.0:443").await?;
        let (mut stream, _) = listener.accept().await?;

        // Send first
        stream.write_all(b"server_hello").await?;

        // Then receive
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"client_hello");

        Ok(())
    });

    sim.client("client", async {
        let mut stream = TcpStream::connect("server:443").await?;

        // Receive first
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await?;
        assert_eq!(&buf[..n], b"server_hello");

        // Then send
        stream.write_all(b"client_hello").await?;

        Ok(())
    });

    sim.run().expect("simulation failed");
}

#[test]
fn large_message_transfer() {
    const MSG_SIZE: usize = 8192;

    let mut sim = turmoil::Builder::new().build();

    sim.host("server", || async {
        let listener = TcpListener::bind("0.0.0.0:443").await?;
        let (mut stream, _) = listener.accept().await?;

        let mut buf = vec![0u8; MSG_SIZE];
        stream.read_exact(&mut buf).await?;

        // Verify pattern
        for (i, byte) in buf.iter().enumerate() {
            assert_eq!(*byte, (i % 256) as u8, "data corruption at byte {i}");
        }

        stream.write_all(b"ok").await?;

        Ok(())
    });

    sim.client("client", async {
        let mut stream = TcpStream::connect("server:443").await?;

        // Send large message with pattern
        let msg: Vec<u8> = (0..MSG_SIZE).map(|i| (i % 256) as u8).collect();
        stream.write_all(&msg).await?;

        // Wait for confirmation
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"ok");

        Ok(())
    });

    sim.run().expect("simulation failed");
}
