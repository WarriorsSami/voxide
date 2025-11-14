use anyhow::{Result, anyhow};
use secrecy::{SecretBox, SecretString};
use sqlx::{Pool, Sqlite};
use std::fs;
use std::io::Write;
use zeroize::Zeroizing;

use crate::crypto::{
    ad_for, create_verifier, derive_key, generate_nonce, generate_salt, open, seal, verify_key,
};
use crate::db::{EntryRepo, MetaRepo, create_pool, ensure_schema};
use crate::dto::*;
use crate::models::{EntryPayload, KdfParams, NewEntry};

/// VaultService handles all vault operations
pub struct VaultService {
    pool: Pool<Sqlite>,
}

impl VaultService {
    /// Open an existing vault or create a new connection
    pub async fn open(vault_path: &str) -> Result<Self> {
        let pool = create_pool(vault_path).await?;
        Ok(Self { pool })
    }

    /// Initialize a new vault with master password
    pub async fn init(&self, dto: InitVaultDto) -> Result<()> {
        // Ensure schema exists
        ensure_schema(&self.pool).await?;

        // Check if vault is already initialized
        if MetaRepo::get(&self.pool).await?.is_some() {
            anyhow::bail!("Vault is already initialized");
        }

        // Generate salt and derive key
        let salt = generate_salt();
        let params = KdfParams::default();
        let key = derive_key(&dto.master_password, &salt, &params)?;

        // Create verifier
        let (verifier_nonce, verifier_ct) = create_verifier(&key)?;

        // Store metadata
        let kdf_params_json = serde_json::to_string(&params)?;

        let metadata = InitMetaDto {
            version: 1,
            kdf_salt: salt.to_vec(),
            kdf_params: kdf_params_json,
            verifier_nonce,
            verifier_ct,
        };

        MetaRepo::insert(&self.pool, metadata).await?;

        println!("✓ Vault initialized successfully");
        Ok(())
    }

    /// Verify master password without returning the key (public unlock guard)
    pub async fn verify_unlock(&self, master_password: &SecretString) -> Result<()> {
        let _key = self.unlock(master_password).await?;
        Ok(())
    }

    /// Unlock vault and return derived key (private helper)
    async fn unlock(&self, master_password: &SecretString) -> Result<SecretBox<[u8; 32]>> {
        let meta = MetaRepo::get(&self.pool)
            .await?
            .ok_or_else(|| anyhow!("Vault not initialized"))?;

        let params = meta.kdf_params_parse()?;
        let key = derive_key(master_password, &meta.kdf_salt, &params)?;

        // Verify the key
        verify_key(&key, &meta.verifier_nonce, &meta.verifier_ct)?;

        Ok(key)
    }

    /// Add a new entry to the vault
    pub async fn add(&self, dto: AddEntryDto) -> Result<()> {
        // Unlock vault
        let key = self.unlock(&dto.master_password).await?;

        // Check if entry already exists
        if EntryRepo::by_pair(&self.pool, dto.service.as_ref(), dto.username.as_ref())
            .await?
            .is_some()
        {
            anyhow::bail!("Entry already exists for {}/{}", dto.service, dto.username);
        }

        // Create payload
        let payload = EntryPayload {
            password: dto.password.into_inner(),
            notes: dto.notes.map(|n| n.into_inner()),
        };
        let payload_json = Zeroizing::new(serde_json::to_vec(&payload)?);

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
            ciphertext,
        };

        EntryRepo::insert(&self.pool, new_entry).await?;

        println!("✓ Added entry for {}/{}", dto.service, dto.username);
        Ok(())
    }

    /// Get an entry from the vault
    pub async fn get(&self, dto: GetEntryDto) -> Result<EntryPayloadDto> {
        // Unlock vault
        let key = self.unlock(&dto.master_password).await?;

        // Fetch entry
        let entry = EntryRepo::by_pair(&self.pool, dto.service.as_ref(), dto.username.as_ref())
            .await?
            .ok_or_else(|| anyhow!("Entry not found"))?;

        // Prepare nonce and AD
        if entry.nonce.len() != 24 {
            anyhow::bail!("Invalid nonce length");
        }
        let nonce: [u8; 24] = entry.nonce.try_into().unwrap();
        let ad = ad_for(dto.service.as_ref(), dto.username.as_ref());

        // Decrypt
        let plaintext = open(&key, &nonce, &entry.ciphertext, &ad)?;

        // Parse payload
        let payload: EntryPayload = serde_json::from_slice(&plaintext)?;

        Ok(payload.into())
    }

    /// List all entries (service/username pairs only)
    pub async fn list(&self) -> Result<Vec<EntryListItemDto>> {
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
    pub async fn delete(&self, dto: DeleteEntryDto) -> Result<()> {
        let rows_affected =
            EntryRepo::delete(&self.pool, dto.service.as_ref(), dto.username.as_ref()).await?;

        if rows_affected == 0 {
            return Err(anyhow!("Entry not found"));
        }

        println!("✓ Deleted entry for {}/{}", dto.service, dto.username);
        Ok(())
    }

    /// Change master password (re-encrypt all entries)
    pub async fn change_master(&self, dto: ChangeMasterDto) -> Result<()> {
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
        let kdf_params_json = serde_json::to_string(&params)?;

        let metadata = InitMetaDto {
            version: 1,
            kdf_salt: new_salt.to_vec(),
            kdf_params: kdf_params_json,
            verifier_nonce: new_verifier_nonce,
            verifier_ct: new_verifier_ct,
        };

        MetaRepo::insert(&temp_pool, metadata).await?;

        // Re-encrypt and insert all entries
        for entry in entries {
            // Decrypt with old key
            let nonce: [u8; 24] = entry
                .nonce
                .clone()
                .try_into()
                .map_err(|_| anyhow!("Invalid nonce"))?;
            let ad = ad_for(&entry.service, &entry.username);
            let plaintext = open(&old_key, &nonce, &entry.ciphertext, &ad)?;

            // Encrypt with new key
            let new_nonce = generate_nonce();
            let new_ciphertext = seal(&new_key, &new_nonce, &plaintext, &ad)?;

            // Insert into temp database
            let new_entry = NewEntry {
                service: entry.service,
                username: entry.username,
                nonce: new_nonce.to_vec(),
                ciphertext: new_ciphertext,
            };
            EntryRepo::insert(&temp_pool, new_entry).await?;
        }

        // Close pools
        temp_pool.close().await;
        self.pool.close().await;

        // Atomic rename
        fs::rename(&temp_path, &dto.vault_path)?;

        println!("✓ Master password changed successfully");
        println!("  Please reconnect to the vault");
        Ok(())
    }

    /// Export vault to encrypted JSON bundle
    pub async fn export(&self, dto: ExportVaultDto) -> Result<()> {
        // Unlock vault (verify password)
        let _key = self.unlock(&dto.master_password).await?;

        // Fetch metadata
        let meta = MetaRepo::get(&self.pool)
            .await?
            .ok_or_else(|| anyhow!("Vault not initialized"))?;

        // Fetch all entries
        let entries = EntryRepo::list_all(&self.pool).await?;

        // Build export DTO
        let export_data = ExportedVaultDto::from_vault_data(&meta, &entries);

        // Serialize to JSON and write to file
        let json_str = serde_json::to_string_pretty(&export_data)?;
        let mut file = fs::File::create(&dto.export_path)?;
        file.write_all(json_str.as_bytes())?;

        println!(
            "✓ Exported {} entries to {}",
            entries.len(),
            dto.export_path
        );
        Ok(())
    }

    /// Import vault from encrypted JSON bundle
    pub async fn import(&self, dto: ImportVaultDto) -> Result<()> {
        // Ensure schema exists
        ensure_schema(&self.pool).await?;

        // Check if vault is already initialized
        if MetaRepo::get(&self.pool).await?.is_some() {
            return Err(anyhow!(
                "Vault is already initialized. Use a new vault file for import."
            ));
        }

        // Read and deserialize import file
        let json_str = fs::read_to_string(&dto.import_path)?;
        let import_data: ExportedVaultDto = serde_json::from_str(&json_str)?;

        // Decode and insert metadata
        let metadata = import_data.decode_metadata()?;
        MetaRepo::insert(&self.pool, metadata).await?;

        // Verify the password works
        let _key = self.unlock(&dto.master_password).await?;

        // Import entries
        for entry_dto in &import_data.entries {
            let (nonce, ciphertext) = entry_dto.decode_for_db()?;

            let new_entry = NewEntry {
                service: entry_dto.service.clone(),
                username: entry_dto.username.clone(),
                nonce,
                ciphertext,
            };
            EntryRepo::insert(&self.pool, new_entry).await?;
        }

        println!(
            "✓ Imported {} entries from {}",
            import_data.entries.len(),
            dto.import_path
        );
        Ok(())
    }
}
