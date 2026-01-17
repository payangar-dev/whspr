use sqlx::{sqlite::SqlitePool, FromRow};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("user already exists: {0}")]
    UserAlreadyExists(String),
}

#[derive(Debug, Clone, FromRow)]
pub struct StoredUser {
    pub username: String,
    pub identity_key: Vec<u8>,
    pub prekey: Vec<u8>,
    pub prekey_signature: Vec<u8>,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct UserStore {
    pool: SqlitePool,
}

impl UserStore {
    pub async fn new(database_url: &str) -> Result<Self, StoreError> {
        let pool = SqlitePool::connect(database_url).await?;

        // Run migrations
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                identity_key BLOB NOT NULL,
                prekey BLOB NOT NULL,
                prekey_signature BLOB NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    pub async fn register_user(
        &self,
        username: &str,
        identity_key: &[u8],
        prekey: &[u8],
        prekey_signature: &[u8],
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO users (username, identity_key, prekey, prekey_signature) VALUES (?, ?, ?, ?)"
        )
        .bind(username)
        .bind(identity_key)
        .bind(prekey)
        .bind(prekey_signature)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                Err(StoreError::UserAlreadyExists(username.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get_user(&self, username: &str) -> Result<StoredUser, StoreError> {
        sqlx::query_as::<_, StoredUser>(
            "SELECT username, identity_key, prekey, prekey_signature, created_at FROM users WHERE username = ?"
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| StoreError::UserNotFound(username.to_string()))
    }

    pub async fn user_exists(&self, username: &str) -> Result<bool, StoreError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0 > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_registration() {
        let store = UserStore::new("sqlite::memory:").await.unwrap();

        let identity_key = [1u8; 32];
        let prekey = [2u8; 32];
        let signature = [3u8; 64];

        store
            .register_user("brave-falcon", &identity_key, &prekey, &signature)
            .await
            .unwrap();

        let user = store.get_user("brave-falcon").await.unwrap();
        assert_eq!(user.username, "brave-falcon");
        assert_eq!(user.identity_key, identity_key);
    }

    #[tokio::test]
    async fn test_duplicate_user() {
        let store = UserStore::new("sqlite::memory:").await.unwrap();

        store
            .register_user("brave-falcon", &[1u8; 32], &[2u8; 32], &[3u8; 64])
            .await
            .unwrap();

        let result = store
            .register_user("brave-falcon", &[1u8; 32], &[2u8; 32], &[3u8; 64])
            .await;

        assert!(matches!(result, Err(StoreError::UserAlreadyExists(_))));
    }
}
