use crate::dto::InitMetaDto;
use crate::errors::{VaultError, VaultResult};
use crate::models::{Entry, EntryPair, Meta, NewEntry};
use sqlx::{Pool, Sqlite, SqlitePool};
use time::OffsetDateTime;

/// Create a SQLite connection pool for the vault database
pub async fn create_pool(path: &str) -> VaultResult<Pool<Sqlite>> {
    let url = format!("sqlite://{}?mode=rwc", path);
    Ok(SqlitePool::connect(&url).await?)
}

/// Ensure schema is initialized (run migrations)
pub async fn ensure_schema(pool: &Pool<Sqlite>) -> VaultResult<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| VaultError::Internal(e.to_string()))?;
    Ok(())
}

/// Meta table operations
pub struct MetaRepo;

impl MetaRepo {
    pub async fn get(pool: &Pool<Sqlite>) -> VaultResult<Option<Meta>> {
        let meta = sqlx::query_as::<_, Meta>("SELECT * FROM meta LIMIT 1")
            .fetch_optional(pool)
            .await?;
        Ok(meta)
    }

    pub async fn insert(pool: &Pool<Sqlite>, metadata: InitMetaDto) -> VaultResult<()> {
        let now = OffsetDateTime::now_utc();
        let created_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO meta (version, kdf_salt, kdf_params, created_at, verifier_nonce, verifier_ct)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(metadata.version)
        .bind(metadata.kdf_salt)
        .bind(metadata.kdf_params)
        .bind(&created_at)
        .bind(metadata.verifier_nonce)
        .bind(metadata.verifier_ct)
        .execute(pool)
        .await?;

        Ok(())
    }
}

/// Entry table operations
pub struct EntryRepo;

impl EntryRepo {
    pub async fn by_pair(
        pool: &Pool<Sqlite>,
        service: &str,
        username: &str,
    ) -> VaultResult<Option<Entry>> {
        let entry = sqlx::query_as::<_, Entry>(
            "SELECT * FROM entries WHERE service = ?1 AND username = ?2",
        )
        .bind(service)
        .bind(username)
        .fetch_optional(pool)
        .await?;
        Ok(entry)
    }

    pub async fn insert(pool: &Pool<Sqlite>, new_entry: NewEntry) -> VaultResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let timestamp = now
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| VaultError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO entries (id, service, username, nonce, ciphertext, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(id)
        .bind(new_entry.service)
        .bind(new_entry.username)
        .bind(new_entry.nonce)
        .bind(new_entry.ciphertext)
        .bind(&timestamp)
        .bind(&timestamp)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn delete(pool: &Pool<Sqlite>, service: &str, username: &str) -> VaultResult<u64> {
        let result = sqlx::query("DELETE FROM entries WHERE service = ?1 AND username = ?2")
            .bind(service)
            .bind(username)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn list_pairs(
        pool: &Pool<Sqlite>,
        pattern: Option<String>,
    ) -> VaultResult<Vec<EntryPair>> {
        let rows = match pattern {
            Some(pattern) => sqlx::query_as::<_, EntryPair>(
                "SELECT service, username, created_at FROM entries
                WHERE service LIKE ?1 OR username LIKE ?1 COLLATE NOCASE ORDER BY service, username",
            )
                .bind(format!("%{pattern}%")),
            None => sqlx::query_as::<_, EntryPair>(
                "SELECT service, username, created_at FROM entries ORDER BY service, username",
            )
        }
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    pub async fn list_all(pool: &Pool<Sqlite>) -> VaultResult<Vec<Entry>> {
        let entries = sqlx::query_as::<_, Entry>("SELECT * FROM entries")
            .fetch_all(pool)
            .await?;
        Ok(entries)
    }
}
