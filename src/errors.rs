use serde_json::Error as SerdeError;
use sqlx::error::Error as SqlxError;
use std::io::Error as IoError;
use thiserror::Error;

pub type VaultResult<T> = Result<T, VaultError>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Vault already initialized")]
    AlreadyInitialized,
    #[error("Vault not initialized")]
    NotInitialized,
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Entry already exists")]
    EntryExists,
    #[error("Entry not found")]
    EntryNotFound,
    #[error("Invalid nonce length")]
    InvalidNonce,
    #[error("KDF failed: {0}")]
    KdfFailed(String),
    #[error("Encryption failed")]
    EncryptFailed,
    #[error("Decryption failed")]
    DecryptFailed,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Database error: {source}")]
    Database {
        #[from]
        source: SqlxError,
    },
    #[error("IO error: {source}")]
    Io {
        #[from]
        source: IoError,
    },
    #[error("Internal error: {0}")]
    Internal(String),
}

impl VaultError {
    /// Get user-facing error message with context and helpful guidance
    pub fn user_message(&self) -> String {
        match self {
            Self::AlreadyInitialized => "Vault already initialized.\n\n\
                 The vault file already contains data.\n\
                 Use a different file path or delete the existing vault if you want to start fresh."
                .to_string(),
            Self::NotInitialized => "Vault not initialized.\n\n\
                 Initialize a new vault first with:\n\
                 voxide init"
                .to_string(),
            Self::AuthFailed => "Authentication failed: Incorrect master password.\n\n\
                 The master password you entered does not match the vault.\n\
                 Please try again or check that you're using the correct vault file."
                .to_string(),
            Self::EntryExists => "Entry already exists.\n\n\
                 An entry with this service and username combination is already in the vault.\n\
                 To update it, delete the old entry first."
                .to_string(),
            Self::EntryNotFound => "Entry not found.\n\n\
                 No password entry exists with this service and username combination.\n\
                 Use 'voxide list' to see all stored entries."
                .to_string(),
            Self::DecryptFailed => "Decryption failed.\n\n\
                 The encrypted data could not be decrypted. This may indicate:\n\
                 - Data tampering or corruption\n\
                 - Wrong master password\n\
                 - Vault file damage"
                .to_string(),
            Self::EncryptFailed => "Encryption failed.\n\n\
                 Unable to encrypt the data. This is an internal error.\n\
                 Please try again or report this issue."
                .to_string(),
            Self::InvalidNonce => "Invalid nonce length.\n\n\
                 The encrypted data has an invalid nonce. The vault may be corrupted."
                .to_string(),
            Self::KdfFailed(msg) => {
                format!(
                    "Key derivation failed: {}\n\n\
                     Unable to derive encryption key from master password.\n\
                     This may indicate vault corruption.",
                    msg
                )
            }
            Self::Serialization(msg) => {
                format!(
                    "Data serialization error: {}\n\n\
                     Unable to process vault data format.",
                    msg
                )
            }
            Self::Database { source: msg } => {
                format!(
                    "Database error: {}\n\n\
                     An error occurred while accessing the vault database.",
                    msg
                )
            }
            Self::Io { source: msg } => {
                format!(
                    "I/O error: {}\n\n\
                     Unable to read or write vault files.",
                    msg
                )
            }
            Self::Internal(msg) => {
                format!("Internal error: {}\n\nPlease report this issue.", msg)
            }
        }
    }
}

impl From<SerdeError> for VaultError {
    fn from(e: SerdeError) -> Self {
        Self::Serialization(e.to_string())
    }
}
