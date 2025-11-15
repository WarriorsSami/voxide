use secrecy::SecretString;
use sqlx::{Pool, Sqlite};
use std::fs;
use std::io::Write;
use zeroize::Zeroizing;

use crate::crypto::{
    ad_for, create_verifier, derive_key, generate_nonce, generate_salt, open, seal, verify_key,
};
use crate::crypto_types::{Ciphertext, EncryptionKey, Nonce, Salt};
use crate::db::{EntryRepo, MetaRepo, create_pool, ensure_schema};
use crate::dto::*;
use crate::errors::{VaultError, VaultResult};
use crate::models::{EntryPayload, KdfParams, NewEntry};

/// VaultService handles all vault operations
pub struct VaultService {
    pool: Pool<Sqlite>,
}

impl VaultService {
    /// Open an existing vault or create a new connection
    pub async fn open(vault_path: &str) -> VaultResult<Self> {
        let pool = create_pool(vault_path).await?;
        Ok(Self { pool })
    }

    /// Initialize a new vault with master password
    pub async fn init(&self, dto: InitVaultDto) -> VaultResult<()> {
        // Ensure schema exists
        ensure_schema(&self.pool).await?;

        // Check if vault is already initialized
        if MetaRepo::get(&self.pool).await?.is_some() {
            return Err(VaultError::AlreadyInitialized);
        }

        // Generate salt and derive key
        let salt = generate_salt();
        let params = KdfParams::default();
        let key = derive_key(&dto.master_password, &salt, &params)?;

        // Create verifier
        let (verifier_nonce, verifier_ct) = create_verifier(&key)?;

        // Store metadata
        let kdf_params_json = serde_json::to_string(&params).map_err(VaultError::from)?;

        let metadata = InitMetaDto {
            version: 1,
            kdf_salt: salt.to_vec(),
            kdf_params: kdf_params_json,
            verifier_nonce: verifier_nonce.to_vec(),
            verifier_ct: verifier_ct.into_vec(),
        };

        MetaRepo::insert(&self.pool, metadata).await?;

        Ok(())
    }

    /// Verify master password without returning the key (public unlock guard)
    pub async fn verify_unlock(&self, master_password: &SecretString) -> VaultResult<()> {
        let _ = self.unlock(master_password).await?;
        Ok(())
    }

    /// Unlock vault and return derived key (private helper)
    async fn unlock(&self, master_password: &SecretString) -> VaultResult<EncryptionKey> {
        let meta = MetaRepo::get(&self.pool)
            .await?
            .ok_or(VaultError::NotInitialized)?;
        let params = meta.kdf_params_parse()?;
        let salt = Salt::try_from_slice(&meta.kdf_salt)?;
        let key = derive_key(master_password, &salt, &params)?;

        // Verify the key
        let verifier_nonce = Nonce::try_from_slice(&meta.verifier_nonce)?;
        let verifier_ct = Ciphertext::from_slice(&meta.verifier_ct);
        verify_key(&key, &verifier_nonce, &verifier_ct)?;

        Ok(key)
    }

    /// Add a new entry to the vault
    pub async fn add(&self, dto: AddEntryDto) -> VaultResult<()> {
        // Unlock vault
        let key = self.unlock(&dto.master_password).await?;

        // Check if entry already exists
        if EntryRepo::by_pair(&self.pool, dto.service.as_ref(), dto.username.as_ref())
            .await?
            .is_some()
        {
            return Err(VaultError::EntryExists);
        }

        // Create payload
        let payload = EntryPayload {
            password: dto.password.into_inner(),
            notes: dto.notes.map(|n| n.into_inner()),
        };
        let payload_json = Zeroizing::new(serde_json::to_vec(&payload).map_err(VaultError::from)?);

        // Generate nonce and AD
        let nonce = generate_nonce();
        let ad = ad_for(dto.service.as_ref(), dto.username.as_ref());

        // Encrypt
        let ciphertext = seal(&key, &nonce, &payload_json, &ad)?;

        // Insert entry
        let new_entry = NewEntry {
            service: dto.service.as_ref().to_string(),
            username: dto.username.as_ref().to_string(),
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.into_vec(),
        };

        EntryRepo::insert(&self.pool, new_entry).await?;

        Ok(())
    }

    /// Get an entry from the vault
    pub async fn get(&self, dto: GetEntryDto) -> VaultResult<EntryPayloadDto> {
        // Unlock vault
        let key = self.unlock(&dto.master_password).await?;

        // Fetch entry
        let entry = EntryRepo::by_pair(&self.pool, dto.service.as_ref(), dto.username.as_ref())
            .await?
            .ok_or(VaultError::EntryNotFound)?;

        // Prepare nonce and AD
        let nonce = Nonce::try_from_slice(&entry.nonce)?;
        let ciphertext = Ciphertext::from_slice(&entry.ciphertext);
        let ad = ad_for(dto.service.as_ref(), dto.username.as_ref());

        // Decrypt
        let plaintext = open(&key, &nonce, &ciphertext, &ad)?;

        // Parse payload
        let payload: EntryPayload = serde_json::from_slice(plaintext.as_bytes()).map_err(VaultError::from)?;

        Ok(payload.into())
    }

    /// List all entries (service/username pairs only)
    pub async fn list(&self) -> VaultResult<Vec<EntryListItemDto>> {
        let pairs = EntryRepo::list_pairs(&self.pool).await?;
        Ok(pairs
            .into_iter()
            .map(|p| EntryListItemDto {
                service: p.service,
                username: p.username,
                created_at: p.created_at,
            })
            .collect())
    }

    /// Delete an entry from the vault
    pub async fn delete(&self, dto: DeleteEntryDto) -> VaultResult<()> {
        let rows =
            EntryRepo::delete(&self.pool, dto.service.as_ref(), dto.username.as_ref()).await?;
        if rows == 0 {
            return Err(VaultError::EntryNotFound);
        }
        Ok(())
    }

    /// Change master password (re-encrypt all entries)
    pub async fn change_master(&self, dto: ChangeMasterDto) -> VaultResult<()> {
        // Unlock with old password
        let old_key = self.unlock(&dto.old_password).await?;

        // Generate new salt and derive new key
        let new_salt = generate_salt();
        let params = KdfParams::default();
        let new_key = derive_key(&dto.new_password, &new_salt, &params)?;

        // Create new verifier
        let (new_verifier_nonce, new_verifier_ct) = create_verifier(&new_key)?;

        // Fetch all entries
        let entries = EntryRepo::list_all(&self.pool).await?;

        // Create temporary database
        let temp_path = format!("{}.tmp", dto.vault_path);
        let temp_pool = create_pool(&temp_path).await?;
        ensure_schema(&temp_pool).await?;

        // Insert new metadata
        let kdf_params_json = serde_json::to_string(&params).map_err(VaultError::from)?;

        let metadata = InitMetaDto {
            version: 1,
            kdf_salt: new_salt.to_vec(),
            kdf_params: kdf_params_json,
            verifier_nonce: new_verifier_nonce.to_vec(),
            verifier_ct: new_verifier_ct.into_vec(),
        };

        MetaRepo::insert(&temp_pool, metadata).await?;

        // Re-encrypt and insert all entries
        for entry in entries {
            // Decrypt with old key
            let nonce = Nonce::try_from_slice(&entry.nonce)?;
            let ciphertext = Ciphertext::from_slice(&entry.ciphertext);
            let ad = ad_for(&entry.service, &entry.username);
            let plaintext = open(&old_key, &nonce, &ciphertext, &ad)?;

            // Encrypt with new key
            let new_nonce = generate_nonce();
            let new_ciphertext = seal(&new_key, &new_nonce, plaintext.as_bytes(), &ad)?;

            // Insert into temp database
            let new_entry = NewEntry {
                service: entry.service,
                username: entry.username,
                nonce: new_nonce.to_vec(),
                ciphertext: new_ciphertext.into_vec(),
            };
            EntryRepo::insert(&temp_pool, new_entry).await?;
        }

        // Close pools
        temp_pool.close().await;
        self.pool.close().await;

        // Atomic rename
        fs::rename(&temp_path, &dto.vault_path).map_err(|e| VaultError::Io(e.to_string()))?;

        Ok(())
    }

    /// Export vault to encrypted JSON bundle
    pub async fn export(&self, dto: ExportVaultDto) -> VaultResult<()> {
        // Unlock vault (verify password)
        let _key = self.unlock(&dto.master_password).await?;

        // Fetch metadata
        let meta = MetaRepo::get(&self.pool)
            .await?
            .ok_or(VaultError::NotInitialized)?;

        // Fetch all entries
        let entries = EntryRepo::list_all(&self.pool).await?;

        // Build export DTO
        let export_data = ExportedVaultDto::from_vault_data(&meta, &entries);

        // Serialize to JSON and write to file
        let json_str = serde_json::to_string_pretty(&export_data).map_err(VaultError::from)?;
        let mut file = fs::File::create(&dto.export_path).map_err(VaultError::from)?;
        file.write_all(json_str.as_bytes())
            .map_err(|e| VaultError::Io(e.to_string()))?;

        Ok(())
    }

    /// Import vault from encrypted JSON bundle
    pub async fn import(&self, dto: ImportVaultDto) -> VaultResult<()> {
        // Ensure schema exists
        ensure_schema(&self.pool).await?;

        // Check if vault is already initialized
        if MetaRepo::get(&self.pool).await?.is_some() {
            return Err(VaultError::AlreadyInitialized);
        }

        // Read and deserialize import file
        let json_str =
            fs::read_to_string(&dto.import_path).map_err(|e| VaultError::Io(e.to_string()))?;
        let import_data: ExportedVaultDto =
            serde_json::from_str(&json_str).map_err(VaultError::from)?;

        // Decode and insert metadata
        let metadata = import_data
            .decode_metadata()
            .map_err(|e| VaultError::Serialization(e.to_string()))?;
        MetaRepo::insert(&self.pool, metadata).await?;

        // Verify the password works
        let _key = self.unlock(&dto.master_password).await?;

        // Import entries
        for entry_dto in &import_data.entries {
            let (nonce, ciphertext) = entry_dto
                .decode_for_db()
                .map_err(|e| VaultError::Serialization(e.to_string()))?;

            let new_entry = NewEntry {
                service: entry_dto.service.clone(),
                username: entry_dto.username.clone(),
                nonce,
                ciphertext,
            };
            EntryRepo::insert(&self.pool, new_entry).await?;
        }

        Ok(())
    }
}
