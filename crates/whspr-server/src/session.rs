use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use whspr_protocol::Frame;

pub type MessageSender = mpsc::Sender<Frame>;

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, MessageSender>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, username: String, sender: MessageSender) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(username, sender);
    }

    pub async fn unregister(&self, username: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(username);
    }

    pub async fn get(&self, username: &str) -> Option<MessageSender> {
        let sessions = self.sessions.read().await;
        sessions.get(username).cloned()
    }

    pub async fn is_online(&self, username: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(username)
    }

    pub async fn online_users(&self) -> Vec<String> {
        let sessions = self.sessions.read().await;
        sessions.keys().cloned().collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
