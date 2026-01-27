//! Turmoil-based Transport implementation using TCP streams.

use std::{io, net::SocketAddr};

use async_trait::async_trait;
use lockframe_core::transport::{Transport, TransportConnection};
use tokio::io::{ReadHalf, WriteHalf};
use turmoil::net::{TcpListener, TcpStream};

/// Simulation transport using Turmoil's deterministic TCP streams.
///
/// Provides deterministic delivery (Turmoil controls packet ordering and
/// timing), fault injection (packet loss, delays, partitions), and reliable
/// ordered byte delivery like QUIC streams.
///
/// We use TCP instead of QUIC because Quinn doesn't support pluggable time/RNG,
/// and Lockframe's protocol logic lives inside QUIC streams anyway - TCP
/// provides identical stream guarantees for testing protocol correctness. Like
/// Quinn's Endpoint, can both accept and initiate connections.
pub struct SimTransport {
    listener: Option<TcpListener>,
}

/// Simulated connection over TCP.
///
/// Wraps a `TcpStream` and provides QUIC-like semantics for testing. Unlike
/// QUIC's multiple concurrent streams, TCP provides only one bidirectional byte
/// stream - sufficient for testing protocol logic without QUIC multiplexing
/// complexity.
pub struct SimConnection {
    stream: TcpStream,
}

impl SimConnection {
    /// Split the connection into send and receive halves.
    ///
    /// This consumes the connection and returns the underlying TCP stream
    /// halves. This is a convenience method for tests that don't need true
    /// QUIC semantics.
    ///
    /// Returns `(send, recv)` for consistency with test usage patterns.
    #[must_use]
    pub fn into_split(self) -> (WriteHalf<TcpStream>, ReadHalf<TcpStream>) {
        let (recv, send) = tokio::io::split(self.stream);
        (send, recv)
    }
}

impl SimTransport {
    /// Creates a server endpoint bound to the specified address.
    ///
    /// This endpoint can accept incoming connections via the Transport trait.
    pub async fn bind(address: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        Ok(Self { listener: Some(listener) })
    }

    /// Creates a client endpoint that can initiate connections.
    ///
    /// Unlike `bind()`, this doesn't bind to a specific address - it's for
    /// clients that only need to connect to servers.
    ///
    /// Use the Transport trait's `connect()` method to establish connections.
    #[must_use]
    pub fn client() -> Self {
        Self { listener: None }
    }

    /// Helper to connect using Turmoil hostname resolution.
    ///
    /// This is a convenience wrapper that accepts hostnames like "server:443"
    /// and resolves them using Turmoil's internal DNS before calling the
    /// Transport trait's `connect()` method.
    pub async fn connect_to_host(&self, address: &str) -> io::Result<SimConnection> {
        // Turmoil's TcpStream::connect accepts hostname strings directly
        let stream = TcpStream::connect(address).await?;
        Ok(SimConnection { stream })
    }
}

#[async_trait]
impl Transport for SimTransport {
    type Connection = SimConnection;

    async fn accept(&self) -> io::Result<Self::Connection> {
        match &self.listener {
            Some(listener) => {
                let (stream, _address) = listener.accept().await?;
                Ok(SimConnection { stream })
            },
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "cannot accept on client endpoint - use SimTransport::bind() for servers",
            )),
        }
    }

    async fn connect(&self, remote: SocketAddr) -> io::Result<Self::Connection> {
        // Turmoil's TcpStream::connect() accepts SocketAddr directly
        // For hostname resolution in tests, use turmoil's lookup mechanism
        let stream = TcpStream::connect(remote).await?;
        Ok(SimConnection { stream })
    }
}

#[async_trait]
impl TransportConnection for SimConnection {
    type SendStream = WriteHalf<TcpStream>;
    type RecvStream = ReadHalf<TcpStream>;

    async fn open_bi(&self) -> io::Result<(Self::SendStream, Self::RecvStream)> {
        // In a real QUIC implementation, this would create a new stream over the
        // connection. For our TCP simulation, we can't do true multiplexing -
        // the caller will need to handle framing at the protocol layer.
        //
        // For now, this is a limitation: only one stream per connection.
        // This matches our current test usage where we create one connection per test.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "open_bi not supported in SimConnection - use accept_bi or split the connection at creation time",
        ))
    }

    async fn accept_bi(&self) -> io::Result<Option<(Self::SendStream, Self::RecvStream)>> {
        // Similar limitation - we can't accept multiple streams on TCP.
        // The connection is already established; we just need to split it.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "accept_bi not supported in SimConnection - use split at creation time",
        ))
    }

    fn close(&self, _error_code: u64, _reason: &str) {
        // TcpStream doesn't have an explicit close with error code.
        // Dropping the stream will close the connection.
        // We can't actually drop self here since we only have &self.
        // The real close happens when SimConnection is dropped.
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn sim_transport_echo() {
        let mut sim = turmoil::Builder::new().build();

        // Server: echo back whatever is received
        sim.host("server", || async {
            let transport = SimTransport::bind("0.0.0.0:443").await?;
            let conn = transport.accept().await?;
            let (mut send, mut recv) = conn.into_split();

            let mut buf = [0u8; 128];
            let n = recv.read(&mut buf).await?;

            send.write_all(&buf[..n]).await?;

            Ok(())
        });

        // Client: send message, verify echo
        sim.client("client", async {
            let transport = SimTransport::client();
            let conn = transport.connect_to_host("server:443").await?;
            let (mut send, mut recv) = conn.into_split();

            let message = b"Hello, Lockframe!";
            send.write_all(message).await?;

            let mut buf = vec![0u8; message.len()];
            recv.read_exact(&mut buf).await?;

            assert_eq!(&buf, message);

            Ok(())
        });

        sim.run().expect("simulation failed");
    }

    #[test]
    fn sim_transport_bidirectional() {
        let mut sim = turmoil::Builder::new().build();

        // Server: send "pong" when receiving "ping"
        sim.host("server", || async {
            let transport = SimTransport::bind("0.0.0.0:443").await?;
            let conn = transport.accept().await?;
            let (mut send, mut recv) = conn.into_split();

            let mut buf = [0u8; 4];
            recv.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"ping");

            send.write_all(b"pong").await?;

            Ok(())
        });

        // Client: send "ping", expect "pong"
        sim.client("client", async {
            let transport = SimTransport::client();
            let conn = transport.connect_to_host("server:443").await?;
            let (mut send, mut recv) = conn.into_split();

            send.write_all(b"ping").await?;

            let mut buf = [0u8; 4];
            recv.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"pong");

            Ok(())
        });

        sim.run().expect("simulation failed");
    }
}
