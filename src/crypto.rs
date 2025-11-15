use argon2::{
    Argon2, ParamsBuilder, Version,
    password_hash::{PasswordHasher, SaltString},
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::crypto_types::{AssociatedData, Ciphertext, EncryptionKey, Nonce, Plaintext, Salt};
use crate::errors::{VaultError, VaultResult};
use crate::models::KdfParams;

const VERIFIER_PLAINTEXT: &[u8] = b"voxide-ok";

/// Derive a 32-byte key from master password using Argon2id
pub fn derive_key(
    password: &SecretString,
    salt: &Salt,
    params: &KdfParams,
) -> VaultResult<EncryptionKey> {
    let argon2_params = ParamsBuilder::new()
        .m_cost(params.m_cost_kib)
        .t_cost(params.t_cost)
        .p_cost(params.p_cost)
        .output_len(params.key_len as usize)
        .build()
        .map_err(|e| VaultError::KdfFailed(format!("Invalid KDF parameters: {}", e)))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    let salt_string = SaltString::encode_b64(salt.as_bytes())
        .map_err(|e| VaultError::KdfFailed(format!("Invalid salt: {}", e)))?;

    let hash = argon2
        .hash_password(password.expose_secret().as_bytes(), &salt_string)
        .map_err(|e| VaultError::KdfFailed(e.to_string()))?;

    let hash_output = hash
        .hash
        .ok_or_else(|| VaultError::KdfFailed("No hash output".to_string()))?;

    let key_bytes = hash_output.as_bytes();

    if key_bytes.len() != 32 {
        return Err(VaultError::KdfFailed("Invalid key length".to_string()));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);

    Ok(EncryptionKey::new(SecretBox::new(Box::new(key_array))))
}

/// Generate a random 16-byte salt for KDF
pub fn generate_salt() -> Salt {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    Salt::new(salt)
}

/// Generate a random 24-byte nonce for XChaCha20-Poly1305
pub fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    Nonce::new(nonce)
}

/// Build associated data from service and username (length-prefix encoding)
pub fn ad_for(service: &str, username: &str) -> AssociatedData {
    let mut ad = Vec::new();
    ad.extend_from_slice(&(service.len() as u32).to_be_bytes());
    ad.extend_from_slice(service.as_bytes());
    ad.extend_from_slice(&(username.len() as u32).to_be_bytes());
    ad.extend_from_slice(username.as_bytes());
    AssociatedData::new(ad)
}

/// Seal (encrypt) plaintext with XChaCha20-Poly1305
pub fn seal(
    key: &EncryptionKey,
    nonce: &Nonce,
    plaintext: &[u8],
    ad: &AssociatedData,
) -> VaultResult<Ciphertext> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| VaultError::EncryptFailed)?;

    let payload = Payload {
        msg: plaintext,
        aad: ad.as_bytes(),
    };

    let ciphertext = cipher
        .encrypt(nonce.as_bytes().into(), payload)
        .map_err(|_| VaultError::EncryptFailed)?;

    Ok(Ciphertext::new(ciphertext))
}

/// Open (decrypt) ciphertext with XChaCha20-Poly1305
pub fn open(
    key: &EncryptionKey,
    nonce: &Nonce,
    ciphertext: &Ciphertext,
    ad: &AssociatedData,
) -> VaultResult<Plaintext> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|_| VaultError::DecryptFailed)?;

    let payload = Payload {
        msg: ciphertext.as_bytes(),
        aad: ad.as_bytes(),
    };

    let plaintext = cipher
        .decrypt(nonce.as_bytes().into(), payload)
        .map_err(|_| VaultError::DecryptFailed)?;

    Ok(Plaintext::new(zeroize::Zeroizing::new(plaintext)))
}

/// Create a verifier ciphertext for the given key
pub fn create_verifier(key: &EncryptionKey) -> VaultResult<(Nonce, Ciphertext)> {
    let nonce = generate_nonce();
    let ciphertext = seal(key, &nonce, VERIFIER_PLAINTEXT, &AssociatedData::empty())?;
    Ok((nonce, ciphertext))
}

/// Verify the derived key by decrypting the verifier
pub fn verify_key(key: &EncryptionKey, nonce: &Nonce, ciphertext: &Ciphertext) -> VaultResult<()> {
    let plaintext = open(key, nonce, ciphertext, &AssociatedData::empty())?;

    if plaintext.as_bytes() == VERIFIER_PLAINTEXT {
        Ok(())
    } else {
        Err(VaultError::AuthFailed)
    }
}
