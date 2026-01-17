mod config;

use config::ServerConfig;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

fn generate_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate certificate");

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    (vec![cert_der], key_der)
}

fn configure_server() -> QuinnServerConfig {
    let (certs, key) = generate_self_signed_cert();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to create TLS config");

    server_crypto.alpn_protocols = vec![b"whspr".to_vec()];

    QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .expect("Failed to create QUIC config")
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .init();

    let config = ServerConfig::default();
    let server_config = configure_server();

    let endpoint = Endpoint::server(server_config, config.listen_addr)?;

    info!("whspr-server listening on {}", config.listen_addr);

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    info!("New connection from {}", connection.remote_address());
                    // TODO: Handle connection
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}
