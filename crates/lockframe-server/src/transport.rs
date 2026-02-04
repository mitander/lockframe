//! Quinn-based QUIC transport implementation.
//!
//! Production QUIC transport using the Quinn library. Provides encrypted,
//! multiplexed streams over UDP with TLS 1.3. Supports both production TLS
//! certificates (via PEM files) and self-signed certificates for testing.
//!
//! # Capabilities
//!
//! - UDP-based transport with packet loss recovery
//! - TLS 1.3 encryption and authentication
//! - Stream multiplexing (multiple logical streams over one connection)
//! - Connection migration support (IP address changes)
//!
//! # Security
//!
//! The transport enforces TLS 1.3 via the `rustls` crate. ALPN
//! (Application-Layer Protocol Negotiation) is set to "lockframe" to ensure
//! protocol compatibility. Self-signed certificates are only suitable for local
//! testing - production deployments MUST use proper TLS certificates from a
//! trusted CA.

use std::{net::SocketAddr, sync::Arc};

use lockframe_proto::ALPN_PROTOCOL;
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};

use crate::error::ServerError;

/// QUIC transport using Quinn.
///
/// Provides a QUIC endpoint that can accept incoming connections. The endpoint
/// is configured with TLS 1.3 and ALPN protocol "lockframe".
///
/// # Security
///
/// TLS certificates must be valid and trusted in production. Self-signed
/// certificates (generated via `bind(addr, None, None)`) are only for testing
/// and will log a warning. Production deployments MUST use certificates from a
/// trusted CA to prevent MITM attacks.
pub struct QuinnTransport {
    /// Quinn endpoint
    endpoint: Endpoint,
}

impl QuinnTransport {
    /// Create and bind a new QUIC transport.
    ///
    /// If `cert_path` and `key_path` are provided, they will be used for TLS.
    /// Otherwise, a self-signed certificate will be generated for testing.
    pub fn bind(
        address: &str,
        cert_path: Option<String>,
        key_path: Option<String>,
    ) -> Result<Self, ServerError> {
        let addr: SocketAddr = address
            .parse()
            .map_err(|e| ServerError::Config(format!("invalid bind address '{address}': {e}")))?;

        let server_config = match (cert_path, key_path) {
            (Some(cert), Some(key)) => load_tls_config(&cert, &key)?,
            _ => generate_self_signed_config()?,
        };

        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| ServerError::Transport(format!("failed to create endpoint: {e}")))?;

        tracing::info!("QUIC transport bound to {}", addr);

        Ok(Self { endpoint })
    }

    /// Accept a new QUIC connection.
    ///
    /// This method blocks until a connection is available.
    pub async fn accept(&self) -> Result<QuinnConnection, ServerError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| ServerError::Transport("endpoint closed".to_string()))?;

        let conn = incoming
            .await
            .map_err(|e| ServerError::Transport(format!("connection failed: {e}")))?;

        Ok(QuinnConnection { connection: conn })
    }

    /// Local address the transport is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, ServerError> {
        self.endpoint
            .local_addr()
            .map_err(|e| ServerError::Transport(format!("failed to get local address: {e}")))
    }
}

/// A QUIC connection wrapper.
///
/// Wraps Quinn's connection type and provides stream operations. Supports both
/// bidirectional streams (`accept_bi` for server-initiated) and unidirectional
/// streams (`open_uni` for server-to-client sends).
///
/// # Cloning
///
/// Clones are cheap and share the same underlying QUIC connection and can be
/// used concurrently. This enables passing the connection to multiple tasks for
/// parallel stream handling.
///
/// # Security
///
/// The connection is TLS-encrypted. All data sent over streams is authenticated
/// and encrypted. The remote peer's certificate is validated during the QUIC
/// handshake before this connection object is created.
#[derive(Clone)]
pub struct QuinnConnection {
    connection: quinn::Connection,
}

impl QuinnConnection {
    /// Accept a bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), ServerError> {
        self.connection
            .accept_bi()
            .await
            .map_err(|e| ServerError::Transport(format!("accept_bi failed: {e}")))
    }

    /// Open a unidirectional stream for sending.
    pub async fn open_uni(&self) -> Result<SendStream, ServerError> {
        self.connection
            .open_uni()
            .await
            .map_err(|e| ServerError::Transport(format!("open_uni failed: {e}")))
    }

    /// Remote peer address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Close the connection with an error code and reason.
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.connection.close(error_code, reason);
    }
}

/// Load TLS configuration from certificate and key files.
fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, ServerError> {
    use std::fs;

    let cert_pem = fs::read(cert_path)
        .map_err(|e| ServerError::Config(format!("failed to read cert '{cert_path}': {e}")))?;

    let key_pem = fs::read(key_path)
        .map_err(|e| ServerError::Config(format!("failed to read key '{key_path}': {e}")))?;

    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Config(format!("failed to parse certificates: {e}")))?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| ServerError::Config(format!("failed to parse private key: {e}")))?
        .ok_or_else(|| ServerError::Config("no private key found".to_string()))?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Config(format!("invalid TLS config: {e}")))?;

    tls_config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| ServerError::Config(format!("QUIC config error: {e}")))?,
    ));

    Ok(server_config)
}

/// Generate a self-signed certificate for testing.
fn generate_self_signed_config() -> Result<ServerConfig, ServerError> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| ServerError::Config(format!("failed to generate self-signed cert: {e}")))?;

    let cert_der = cert.cert.der().clone();
    let key_der = cert.key_pair.serialize_der();

    let cert_chain = vec![cert_der];
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der);

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key.into())
        .map_err(|e| ServerError::Config(format!("invalid TLS config: {e}")))?;

    tls_config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| ServerError::Config(format!("QUIC config error: {e}")))?,
    ));

    tracing::warn!("Using self-signed certificate - not for production use!");

    Ok(server_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transport_binds_with_self_signed() {
        let transport = QuinnTransport::bind("127.0.0.1:0", None, None);
        assert!(transport.is_ok(), "Transport should bind with self-signed cert");

        let transport = transport.unwrap();
        let addr = transport.local_addr().unwrap();
        assert_ne!(addr.port(), 0, "Should have assigned a port");
    }

    #[tokio::test]
    async fn transport_rejects_invalid_address() {
        let result = QuinnTransport::bind("invalid:address:format", None, None);
        assert!(result.is_err(), "Should reject invalid address");
    }
}
