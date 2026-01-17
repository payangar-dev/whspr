use bytes::BytesMut;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error};

use whspr_protocol::{Frame, decode_payload, encode_payload};

pub struct Client {
    endpoint: Endpoint,
    connection: Option<Connection>,
    send: Option<SendStream>,
    recv: Option<RecvStream>,
}

impl Client {
    pub fn new() -> anyhow::Result<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

        // Configure client to accept self-signed certs (dev only)
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        crypto.alpn_protocols = vec![b"whspr".to_vec()];

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        ));

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        client_config.transport_config(Arc::new(transport));

        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            connection: None,
            send: None,
            recv: None,
        })
    }

    pub async fn connect(&mut self, addr: SocketAddr) -> anyhow::Result<()> {
        let connection = self.endpoint.connect(addr, "localhost")?.await?;
        info!("Connected to server at {}", addr);

        let (send, recv) = connection.open_bi().await?;

        self.connection = Some(connection);
        self.send = Some(send);
        self.recv = Some(recv);

        Ok(())
    }

    pub async fn send_frame(&mut self, frame: Frame) -> anyhow::Result<()> {
        let send = self.send.as_mut().ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        send.write_all(&buf).await?;

        Ok(())
    }

    pub async fn recv_frame(&mut self) -> anyhow::Result<Option<Frame>> {
        let recv = self.recv.as_mut().ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        let mut buf = BytesMut::with_capacity(65536);
        let mut chunk = [0u8; 4096];

        loop {
            // Try to decode a frame from existing buffer
            if let Some(frame) = Frame::decode(&mut buf)? {
                return Ok(Some(frame));
            }

            // Need more data
            match recv.read(&mut chunk).await? {
                Some(n) => buf.extend_from_slice(&chunk[..n]),
                None => return Ok(None),
            }
        }
    }
}

// Skip certificate verification for development
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
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
