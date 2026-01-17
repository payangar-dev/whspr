mod config;
mod connection;
mod queue;
mod session;
mod store;

use config::ServerConfig;
use connection::ConnectionHandler;
use queue::MessageQueue;
use session::SessionManager;
use store::UserStore;

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

    // Initialize stores
    let store = UserStore::new("sqlite:whspr.db?mode=rwc").await?;
    let sessions = SessionManager::new();
    let queue = MessageQueue::new(config.message_ttl_secs);

    // Start cleanup task
    let queue_cleanup = queue.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            queue_cleanup.cleanup_expired().await;
        }
    });

    let endpoint = Endpoint::server(server_config, config.listen_addr)?;

    info!("whspr-server listening on {}", config.listen_addr);

    while let Some(incoming) = endpoint.accept().await {
        let store = store.clone();
        let sessions = sessions.clone();
        let queue = queue.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    info!("New connection from {}", connection.remote_address());
                    let handler = ConnectionHandler::new(connection, store, sessions, queue);
                    handler.run().await;
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        });
    }

    Ok(())
}
