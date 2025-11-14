use crate::dto::InitMetaDto;
use crate::models::{Entry, EntryPair, Meta, NewEntry};
use anyhow::Result;
use sqlx::{Pool, Sqlite, SqlitePool};
use time::OffsetDateTime;

/// Create a SQLite connection pool for the vault database
pub async fn create_pool(path: &str) -> Result<Pool<Sqlite>> {
    let url = format!("sqlite://{}?mode=rwc", path);
    let pool = SqlitePool::connect(&url).await?;
    Ok(pool)
}

/// Ensure schema is initialized (run migrations)
pub async fn ensure_schema(pool: &Pool<Sqlite>) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Meta table operations
pub struct MetaRepo;

impl MetaRepo {
    pub async fn get(pool: &Pool<Sqlite>) -> Result<Option<Meta>> {
        let meta = sqlx::query_as::<_, Meta>("SELECT * FROM meta LIMIT 1")
            .fetch_optional(pool)
            .await?;
        Ok(meta)
    }

    pub async fn insert(pool: &Pool<Sqlite>, metadata: InitMetaDto) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let created_at = now.format(&time::format_description::well_known::Rfc3339)?;

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
    ) -> Result<Option<Entry>> {
        let entry = sqlx::query_as::<_, Entry>(
            "SELECT * FROM entries WHERE service = ?1 AND username = ?2",
        )
        .bind(service)
        .bind(username)
        .fetch_optional(pool)
        .await?;
        Ok(entry)
    }

    pub async fn insert(pool: &Pool<Sqlite>, new_entry: NewEntry) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = OffsetDateTime::now_utc();
        let timestamp = now.format(&time::format_description::well_known::Rfc3339)?;

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

    pub async fn delete(pool: &Pool<Sqlite>, service: &str, username: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM entries WHERE service = ?1 AND username = ?2")
            .bind(service)
            .bind(username)
            .execute(pool)
            .await?;

        Ok(result.rows_affected())
    }

    pub async fn list_pairs(pool: &Pool<Sqlite>) -> Result<Vec<EntryPair>> {
        let rows = sqlx::query_as::<_, (String, String, String)>(
            "SELECT service, username, created_at FROM entries ORDER BY service, username",
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(service, username, created_at)| EntryPair {
                service,
                username,
                created_at,
            })
            .collect())
    }

    pub async fn list_all(pool: &Pool<Sqlite>) -> Result<Vec<Entry>> {
        let entries = sqlx::query_as::<_, Entry>("SELECT * FROM entries")
            .fetch_all(pool)
            .await?;
        Ok(entries)
    }
}
