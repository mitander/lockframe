//! QUIC transport for the client.
//!
//! Provides [`ConnectedClient`] which handles QUIC I/O for frame transport.
//! This is a thin layer that just sends/receives frames - protocol logic
//! remains in the Sans-IO [`Client`].
//!
//! # TLS Modes
//!
//! - Secure (default): Verifies server certificates against system roots. Use
//!   this for production deployments with CA-signed certificates.
//! - Insecure: Accepts any certificate without verification. Use this only for
//!   development with self-signed certificates.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::BytesMut;
use lockframe_proto::{ALPN_PROTOCOL, Frame, FrameHeader};
use quinn::{ClientConfig, Endpoint, ReadExactError, RecvStream, SendStream};
use thiserror::Error;
use tokio::sync::mpsc;
use zerocopy::FromBytes;

const TRANSPORT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TLS verification mode for client connections.
#[derive(Debug, Clone, Copy, Default)]
pub enum TlsMode {
    /// Verify server certificate against system roots (production).
    #[default]
    Secure,
    /// Accept any certificate without verification (development only).
    Insecure,
}

// Configuration for client transport.
//
/// Use [`TransportConfig::default`] for standard settings:
/// - Secure TLS
/// - `server_name = "localhost"`
/// - `connect_timeout` = 5s`
///
/// Convenience constructors are provided for common environments.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// TLS verification mode.
    pub tls_mode: TlsMode,

    /// Server name used for TLS SNI.
    pub server_name: String,

    /// Maximum time to wait for connection establishment.
    pub connect_timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tls_mode: TlsMode::default(),
            server_name: "localhost".to_string(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

impl TransportConfig {
    /// Create config for development environments (insecure TLS).
    pub fn development() -> Self {
        Self { tls_mode: TlsMode::Insecure, ..Default::default() }
    }

    /// Create config for production with an explicit server name.
    pub fn production(server_name: impl Into<String>) -> Self {
        Self { tls_mode: TlsMode::Secure, server_name: server_name.into(), ..Default::default() }
    }
}

/// Transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Connection failed.
    #[error("connection failed: {0}")]
    Connection(String),

    /// Stream error.
    #[error("stream error: {0}")]
    Stream(String),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Handle to a connected client with QUIC transport.
///
/// Provides channels for frame transport. Frames are sent/received via
/// the channels, and an internal task handles the QUIC I/O.
pub struct ConnectedClient {
    /// Send frames to the server.
    pub to_server: mpsc::Sender<Frame>,
    /// Receive frames from the server.
    pub from_server: mpsc::Receiver<Frame>,
    /// Connection errors. Receiving an error means the connection is dead.
    pub errors: mpsc::Receiver<TransportError>,
    /// Abort handle to stop the connection task.
    abort_handle: tokio::task::AbortHandle,
}

impl ConnectedClient {
    /// Stop the connection.
    pub fn stop(&self) {
        self.abort_handle.abort();
    }
}

/// Connect to a Lockframe server via QUIC with default config.
///
/// Uses development mode (insecure TLS) for backwards compatibility.
/// For production, use [`connect_with_config`] with secure TLS.
pub async fn connect(server_addr: &str) -> Result<ConnectedClient, TransportError> {
    connect_with_config(server_addr, TransportConfig::development()).await
}

/// Connect to a Lockframe server via QUIC with custom config.
///
/// # TLS Modes
///
/// - `TlsMode::Secure`: Verifies server certificate against system roots.
/// - `TlsMode::Insecure`: Accepts any certificate (development only).
///
/// # Errors
///
/// Returns `TransportError::Connection` if the connection times out or fails.
pub async fn connect_with_config(
    server_addr: &str,
    config: TransportConfig,
) -> Result<ConnectedClient, TransportError> {
    let addr: SocketAddr = server_addr
        .parse()
        .map_err(|e| TransportError::Connection(format!("invalid address: {e}")))?;

    let client_config = match config.tls_mode {
        TlsMode::Secure => secure_client_config()?,
        TlsMode::Insecure => insecure_client_config(),
    };
    let mut endpoint =
        Endpoint::client("0.0.0.0:0".parse().expect("invariant: literal socket address is valid"))
            .map_err(|e| TransportError::Connection(format!("endpoint creation failed: {e}")))?;
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint
        .connect(addr, &config.server_name)
        .map_err(|e| TransportError::Connection(format!("connect failed: {e}")))?;

    let connection = tokio::time::timeout(config.connect_timeout, connecting)
        .await
        .map_err(|_| {
            TransportError::Connection(format!(
                "connection timed out after {:?}",
                config.connect_timeout
            ))
        })?
        .map_err(|e| TransportError::Connection(format!("connection failed: {e}")))?;

    let (to_server_tx, to_server_rx) = mpsc::channel::<Frame>(32);
    let (from_server_tx, from_server_rx) = mpsc::channel::<Frame>(32);
    let (error_tx, error_rx) = mpsc::channel::<TransportError>(1);

    let handle = tokio::spawn(run_connection(connection, to_server_rx, from_server_tx, error_tx));

    Ok(ConnectedClient {
        to_server: to_server_tx,
        from_server: from_server_rx,
        errors: error_rx,
        abort_handle: handle.abort_handle(),
    })
}

/// Run the connection, bridging between channels and QUIC.
async fn run_connection(
    connection: quinn::Connection,
    mut to_server: mpsc::Receiver<Frame>,
    from_server: mpsc::Sender<Frame>,
    errors: mpsc::Sender<TransportError>,
) {
    let conn_recv = connection.clone();
    let recv_errors = errors.clone();
    let recv_handle = tokio::spawn(async move {
        match conn_recv.accept_uni().await {
            Ok(recv) => {
                if let Err(e) = read_frames_loop(recv, from_server).await {
                    let _ = recv_errors.send(e).await;
                }
            },
            Err(e) => {
                let err =
                    TransportError::Connection(format!("failed to accept server stream: {e}"));
                let _ = recv_errors.send(err).await;
            },
        }
    });

    let (mut send, _recv) = match connection.open_bi().await {
        Ok(streams) => streams,
        Err(e) => {
            let err = TransportError::Connection(format!("failed to open outbound stream: {e}"));
            let _ = errors.send(err).await;
            recv_handle.abort();
            return;
        },
    };

    while let Some(frame) = to_server.recv().await {
        if let Err(e) = write_frame(&mut send, &frame).await {
            let _ = errors.send(e).await;
            break;
        }
    }

    let _ = send.finish();
    recv_handle.abort();
}

/// Read frames from a persistent stream until it closes.
async fn read_frames_loop(
    mut recv: RecvStream,
    tx: mpsc::Sender<Frame>,
) -> Result<(), TransportError> {
    let mut buf = BytesMut::with_capacity(65536);

    loop {
        buf.clear();
        buf.resize(FrameHeader::SIZE, 0);

        match recv.read_exact(&mut buf[..FrameHeader::SIZE]).await {
            Ok(()) => {},
            Err(ReadExactError::FinishedEarly(0)) => {
                return Ok(());
            },
            Err(e) => {
                return Err(TransportError::Stream(format!("header read failed: {e}")));
            },
        }

        let header: &FrameHeader = FrameHeader::ref_from_bytes(&buf[..FrameHeader::SIZE])
            .map_err(|e| TransportError::Protocol(format!("invalid header: {e}")))?;

        let payload_size = header.payload_size() as usize;

        if payload_size > 0 {
            buf.resize(FrameHeader::SIZE + payload_size, 0);
            recv.read_exact(&mut buf[FrameHeader::SIZE..])
                .await
                .map_err(|e| TransportError::Stream(format!("payload read failed: {e}")))?;
        }

        let frame = Frame::decode(&buf)
            .map_err(|e| TransportError::Protocol(format!("frame decode failed: {e}")))?;

        tx.send(frame)
            .await
            .map_err(|e| TransportError::Stream(format!("channel send failed: {e}")))?;
    }
}

/// Write a frame to a persistent stream
async fn write_frame(send: &mut SendStream, frame: &Frame) -> Result<(), TransportError> {
    let mut buf = Vec::new();
    frame.encode(&mut buf).map_err(|e| TransportError::Protocol(format!("encode failed: {e}")))?;

    send.write_all(&buf).await.map_err(|e| TransportError::Stream(format!("write failed: {e}")))?;

    Ok(())
}

/// Create a secure client config that verifies certificates against system
/// roots.
fn secure_client_config() -> Result<ClientConfig, TransportError> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut crypto =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();

    crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| TransportError::Connection(format!("TLS config error: {e}")))?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        TRANSPORT_IDLE_TIMEOUT
            .try_into()
            .expect("invariant: 30s timeout within IdleTimeout bounds"),
    ));
    config.transport_config(Arc::new(transport));

    Ok(config)
}

/// Create an insecure client config that accepts any certificate.
///
/// WARNING: Development only. Production should use [`secure_client_config`].
fn insecure_client_config() -> ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        .with_no_client_auth();

    crypto.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("rustls config should be valid"),
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        TRANSPORT_IDLE_TIMEOUT
            .try_into()
            .expect("invariant: 30s timeout within IdleTimeout bounds"),
    ));
    config.transport_config(Arc::new(transport));

    config
}

/// Certificate verifier that accepts any certificate (insecure, for
/// development).
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
