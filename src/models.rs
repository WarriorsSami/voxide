use crate::errors::{VaultError, VaultResult};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// KDF parameters for Argon2id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub version: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub key_len: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            version: "0x13".to_string(),
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 1,
            key_len: 32,
        }
    }
}

/// Metadata row (single row per vault)
#[derive(Debug, FromRow)]
pub struct Meta {
    pub version: i64,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: String,
    pub created_at: String,
    pub verifier_nonce: Vec<u8>,
    pub verifier_ct: Vec<u8>,
}

impl Meta {
    pub fn kdf_params_parse(&self) -> VaultResult<KdfParams> {
        serde_json::from_str(&self.kdf_params).map_err(|e| VaultError::Serialization(e.to_string()))
    }
}

/// Entry row (one per service/username pair)
#[derive(Debug, FromRow)]
pub struct Entry {
    pub id: String, // UUID stored as TEXT
    pub service: String,
    pub username: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub created_at: String,
    pub updated_at: String,
}

/// New entry for insertion
pub struct NewEntry {
    pub service: String,
    pub username: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Listing tuple for list command
#[derive(Debug)]
pub struct EntryPair {
    pub service: String,
    pub username: String,
    pub created_at: String,
}

/// Encrypted payload structure
#[derive(Debug, Serialize, Deserialize)]
pub struct EntryPayload {
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}
