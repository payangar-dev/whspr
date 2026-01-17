use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub message_ttl_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:4433".parse().unwrap(),
            message_ttl_secs: 86400, // 24 hours
        }
    }
}
