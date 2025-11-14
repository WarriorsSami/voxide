use crate::domain::*;
use secrecy::SecretString;

/// DTO for initializing metadata (version, salt, params, verifier)
pub struct InitMetaDto {
    pub version: i64,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: String,
    pub verifier_nonce: Vec<u8>,
    pub verifier_ct: Vec<u8>,
}

/// DTO for initializing a new vault
pub struct InitVaultDto {
    pub master_password: SecretString,
}

/// DTO for adding a new entry
pub struct AddEntryDto {
    pub master_password: SecretString,
    pub service: Service,
    pub username: Username,
    pub password: Password,
    pub notes: Option<Notes>,
}

/// DTO for retrieving an entry
pub struct GetEntryDto {
    pub master_password: SecretString,
    pub service: Service,
    pub username: Username,
}

/// DTO for deleting an entry
pub struct DeleteEntryDto {
    pub service: Service,
    pub username: Username,
}

/// DTO for changing master password
pub struct ChangeMasterDto {
    pub old_password: SecretString,
    pub new_password: SecretString,
    pub vault_path: String,
}

/// DTO for exporting vault
pub struct ExportVaultDto {
    pub master_password: SecretString,
    pub export_path: String,
}

/// DTO for importing vault
pub struct ImportVaultDto {
    pub master_password: SecretString,
    pub import_path: String,
}

/// DTO for entry list item (returned from list operation)
#[derive(Debug, Clone)]
pub struct EntryListItemDto {
    pub service: String,
    pub username: String,
    pub created_at: String,
}

/// DTO for entry payload (returned from get operation)
#[derive(Debug, Clone)]
pub struct EntryPayloadDto {
    pub password: String,
    pub notes: Option<String>,
}

impl From<crate::models::EntryPayload> for EntryPayloadDto {
    fn from(payload: crate::models::EntryPayload) -> Self {
        Self {
            password: payload.password,
            notes: payload.notes,
        }
    }
}

/// DTO for exported entry (serializable)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportedEntryDto {
    pub service: String,
    pub username: String,
    pub nonce: String,      // Base64 encoded
    pub ciphertext: String, // Base64 encoded
    pub created_at: String,
    pub updated_at: String,
}

/// DTO for exported vault (serializable)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportedVaultDto {
    pub version: i64,
    pub kdf_salt: String,   // Base64 encoded
    pub kdf_params: String, // JSON string
    pub created_at: String,
    pub verifier_nonce: String, // Base64 encoded
    pub verifier_ct: String,    // Base64 encoded
    pub entries: Vec<ExportedEntryDto>,
}

impl ExportedEntryDto {
    /// Convert from database Entry model with base64 encoding
    pub fn from_entry(entry: &crate::models::Entry) -> Self {
        use base64::{Engine as _, engine::general_purpose};

        Self {
            service: entry.service.clone(),
            username: entry.username.clone(),
            nonce: general_purpose::STANDARD.encode(&entry.nonce),
            ciphertext: general_purpose::STANDARD.encode(&entry.ciphertext),
            created_at: entry.created_at.clone(),
            updated_at: entry.updated_at.clone(),
        }
    }

    /// Decode base64 fields for database insertion
    pub fn decode_for_db(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        use base64::{Engine as _, engine::general_purpose};

        let nonce = general_purpose::STANDARD.decode(&self.nonce)?;
        let ciphertext = general_purpose::STANDARD.decode(&self.ciphertext)?;

        Ok((nonce, ciphertext))
    }
}

impl ExportedVaultDto {
    /// Create from metadata and entries
    pub fn from_vault_data(meta: &crate::models::Meta, entries: &[crate::models::Entry]) -> Self {
        use base64::{Engine as _, engine::general_purpose};

        Self {
            version: meta.version,
            kdf_salt: general_purpose::STANDARD.encode(&meta.kdf_salt),
            kdf_params: meta.kdf_params.clone(),
            created_at: meta.created_at.clone(),
            verifier_nonce: general_purpose::STANDARD.encode(&meta.verifier_nonce),
            verifier_ct: general_purpose::STANDARD.encode(&meta.verifier_ct),
            entries: entries.iter().map(ExportedEntryDto::from_entry).collect(),
        }
    }

    /// Decode metadata fields for database insertion
    pub fn decode_metadata(&self) -> anyhow::Result<InitMetaDto> {
        use base64::{Engine as _, engine::general_purpose};

        Ok(InitMetaDto {
            version: self.version,
            kdf_salt: general_purpose::STANDARD.decode(&self.kdf_salt)?,
            kdf_params: self.kdf_params.clone(),
            verifier_nonce: general_purpose::STANDARD.decode(&self.verifier_nonce)?,
            verifier_ct: general_purpose::STANDARD.decode(&self.verifier_ct)?,
        })
    }
}
