//! QUIC transport for the client.
//!
//! Provides [`ConnectedClient`] which handles QUIC I/O for frame transport.
//! This is a thin layer that just sends/receives frames - protocol logic
//! remains in the Sans-IO [`Client`].

use std::{net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use lockframe_proto::{Frame, FrameHeader};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use thiserror::Error;
use tokio::sync::mpsc;
use zerocopy::FromBytes;

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
    /// Abort handle to stop the connection task.
    abort_handle: tokio::task::AbortHandle,
}

impl ConnectedClient {
    /// Stop the connection.
    pub fn stop(&self) {
        self.abort_handle.abort();
    }
}

/// Connect to a Lockframe server via QUIC.
///
/// Returns a [`ConnectedClient`] with channels for frame transport.
pub async fn connect(server_addr: &str) -> Result<ConnectedClient, TransportError> {
    let addr: SocketAddr = server_addr
        .parse()
        .map_err(|e| TransportError::Connection(format!("invalid address: {e}")))?;

    // Create client endpoint
    let client_config = insecure_client_config();
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| TransportError::Connection(format!("endpoint creation failed: {e}")))?;
    endpoint.set_default_client_config(client_config);

    // Connect to server
    let connection = endpoint
        .connect(addr, "localhost")
        .map_err(|e| TransportError::Connection(format!("connect failed: {e}")))?
        .await
        .map_err(|e| TransportError::Connection(format!("connection failed: {e}")))?;

    let (to_server_tx, to_server_rx) = mpsc::channel::<Frame>(32);
    let (from_server_tx, from_server_rx) = mpsc::channel::<Frame>(32);

    // Spawn connection handler
    let handle = tokio::spawn(run_connection(connection, to_server_rx, from_server_tx));

    Ok(ConnectedClient {
        to_server: to_server_tx,
        from_server: from_server_rx,
        abort_handle: handle.abort_handle(),
    })
}

/// Run the connection, bridging between channels and QUIC.
async fn run_connection(
    connection: quinn::Connection,
    mut to_server: mpsc::Receiver<Frame>,
    from_server: mpsc::Sender<Frame>,
) {
    // Spawn receiver task for incoming unidirectional streams
    let conn_recv = connection.clone();
    let from_server_clone = from_server.clone();
    let recv_handle = tokio::spawn(async move {
        loop {
            match conn_recv.accept_uni().await {
                Ok(recv) => {
                    let tx = from_server_clone.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_incoming_stream(recv, tx).await {
                            eprintln!("Incoming stream error: {e}");
                        }
                    });
                },
                Err(e) => {
                    eprintln!("Accept uni error: {e}");
                    break;
                },
            }
        }
    });

    // Main loop: send outgoing frames
    while let Some(frame) = to_server.recv().await {
        if let Ok((send, _recv)) = connection.open_bi().await {
            if let Err(e) = send_frame(send, &frame).await {
                eprintln!("Send error: {e}");
            }
        }
    }

    recv_handle.abort();
}

/// Handle an incoming unidirectional stream (server -> client).
async fn handle_incoming_stream(
    mut recv: RecvStream,
    tx: mpsc::Sender<Frame>,
) -> Result<(), TransportError> {
    let mut buf = BytesMut::with_capacity(65536);

    // Read header
    buf.resize(FrameHeader::SIZE, 0);
    recv.read_exact(&mut buf[..FrameHeader::SIZE])
        .await
        .map_err(|e| TransportError::Stream(format!("header read failed: {e}")))?;

    let header: &FrameHeader = FrameHeader::ref_from_bytes(&buf[..FrameHeader::SIZE])
        .map_err(|e| TransportError::Protocol(format!("invalid header: {e}")))?;

    let payload_size = header.payload_size() as usize;

    // Read payload if present
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

    Ok(())
}

/// Send a frame on a stream.
async fn send_frame(mut send: SendStream, frame: &Frame) -> Result<(), TransportError> {
    let mut buf = Vec::new();
    frame.encode(&mut buf).map_err(|e| TransportError::Protocol(format!("encode failed: {e}")))?;

    send.write_all(&buf).await.map_err(|e| TransportError::Stream(format!("write failed: {e}")))?;

    send.finish().map_err(|e| TransportError::Stream(format!("finish failed: {e}")))?;

    Ok(())
}

/// Create an insecure client config that accepts any certificate.
///
/// WARNING: Development only. Production should verify certificates.
fn insecure_client_config() -> ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        .with_no_client_auth();

    // Must match server's ALPN protocol
    crypto.alpn_protocols = vec![b"lockframe".to_vec()];

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("rustls config should be valid"),
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
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
