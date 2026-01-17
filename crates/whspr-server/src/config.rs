use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub message_ttl_secs: u64,
    pub db_path: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: std::env::var("WHSPR_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:4433".to_string())
                .parse()
                .expect("Invalid listen address"),
            message_ttl_secs: std::env::var("WHSPR_MESSAGE_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400), // 24 hours
            db_path: std::env::var("WHSPR_DB_PATH")
                .unwrap_or_else(|_| "whspr.db".to_string()),
        }
    }
}
