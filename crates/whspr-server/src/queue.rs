use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub from: String,
    pub ciphertext: Vec<u8>,
    pub timestamp: u64,
    pub key_exchange: Option<(Vec<u8>, Vec<u8>)>, // (identity_key, ephemeral_key)
    queued_at: Instant,
}

#[derive(Clone)]
pub struct MessageQueue {
    queues: Arc<RwLock<HashMap<String, VecDeque<QueuedMessage>>>>,
    ttl: Duration,
}

impl MessageQueue {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            queues: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub async fn enqueue(&self, to: &str, from: String, ciphertext: Vec<u8>, timestamp: u64, key_exchange: Option<(Vec<u8>, Vec<u8>)>) {
        let mut queues = self.queues.write().await;
        let queue = queues.entry(to.to_string()).or_default();

        queue.push_back(QueuedMessage {
            from,
            ciphertext,
            timestamp,
            key_exchange,
            queued_at: Instant::now(),
        });
    }

    pub async fn drain(&self, username: &str) -> Vec<QueuedMessage> {
        let mut queues = self.queues.write().await;
        let Some(queue) = queues.get_mut(username) else {
            return Vec::new();
        };

        let now = Instant::now();

        // Filter out expired messages and drain the rest
        let messages: Vec<_> = queue
            .drain(..)
            .filter(|msg| now.duration_since(msg.queued_at) < self.ttl)
            .collect();

        messages
    }

    pub async fn cleanup_expired(&self) {
        let mut queues = self.queues.write().await;
        let now = Instant::now();

        for queue in queues.values_mut() {
            queue.retain(|msg| now.duration_since(msg.queued_at) < self.ttl);
        }

        // Remove empty queues
        queues.retain(|_, q| !q.is_empty());
    }

    pub async fn pending_count(&self, username: &str) -> usize {
        let queues = self.queues.read().await;
        queues.get(username).map(|q| q.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enqueue_and_drain() {
        let queue = MessageQueue::new(3600);

        queue.enqueue("alice", "bob".to_string(), vec![1, 2, 3], 12345, None).await;
        queue.enqueue("alice", "carol".to_string(), vec![4, 5, 6], 12346, None).await;

        let messages = queue.drain("alice").await;
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].from, "bob");
        assert_eq!(messages[1].from, "carol");

        // Queue should be empty after drain
        let messages = queue.drain("alice").await;
        assert!(messages.is_empty());
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let queue = MessageQueue::new(0); // 0 second TTL = immediate expiry

        queue.enqueue("alice", "bob".to_string(), vec![1, 2, 3], 12345, None).await;

        // Small delay to ensure expiry
        tokio::time::sleep(Duration::from_millis(10)).await;

        let messages = queue.drain("alice").await;
        assert!(messages.is_empty());
    }
}
