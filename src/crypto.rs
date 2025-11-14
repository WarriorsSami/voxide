use anyhow::{Result, anyhow};
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
use zeroize::Zeroizing;

use crate::models::KdfParams;

const VERIFIER_PLAINTEXT: &[u8] = b"voxide-ok";

/// Derive a 32-byte key from master password using Argon2id
pub fn derive_key(
    password: &SecretString,
    salt: &[u8],
    params: &KdfParams,
) -> Result<SecretBox<[u8; 32]>> {
    let argon2_params = ParamsBuilder::new()
        .m_cost(params.m_cost_kib)
        .t_cost(params.t_cost)
        .p_cost(params.p_cost)
        .output_len(params.key_len as usize)
        .build()
        .map_err(|e| anyhow!("Invalid Argon2 params: {}", e))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, argon2_params);

    let salt_string = SaltString::encode_b64(salt).map_err(|e| anyhow!("Invalid salt: {}", e))?;

    let hash = argon2
        .hash_password(password.expose_secret().as_bytes(), &salt_string)
        .map_err(|e| anyhow!("KDF failed: {}", e))?;

    let hash_output = hash.hash.ok_or_else(|| anyhow!("No hash output"))?;

    let key_bytes = hash_output.as_bytes();

    if key_bytes.len() != 32 {
        anyhow::bail!("Invalid key length");
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);

    Ok(SecretBox::new(Box::new(key_array)))
}

/// Generate a random 16-byte salt for KDF
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    salt
}

/// Generate a random 24-byte nonce for XChaCha20-Poly1305
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Build associated data from service and username (length-prefix encoding)
pub fn ad_for(service: &str, username: &str) -> Vec<u8> {
    let mut ad = Vec::new();
    ad.extend_from_slice(&(service.len() as u32).to_be_bytes());
    ad.extend_from_slice(service.as_bytes());
    ad.extend_from_slice(&(username.len() as u32).to_be_bytes());
    ad.extend_from_slice(username.as_bytes());
    ad
}

/// Seal (encrypt) plaintext with XChaCha20-Poly1305
pub fn seal(
    key: &SecretBox<[u8; 32]>,
    nonce: &[u8; 24],
    plaintext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|e| anyhow!("Cipher init failed: {}", e))?;

    let payload = Payload {
        msg: plaintext,
        aad: ad,
    };

    let ciphertext = cipher
        .encrypt(nonce.into(), payload)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok(ciphertext)
}

/// Open (decrypt) ciphertext with XChaCha20-Poly1305
pub fn open(
    key: &SecretBox<[u8; 32]>,
    nonce: &[u8; 24],
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
        .map_err(|e| anyhow!("Cipher init failed: {}", e))?;

    let payload = Payload {
        msg: ciphertext,
        aad: ad,
    };

    let plaintext = cipher
        .decrypt(nonce.into(), payload)
        .map_err(|_| anyhow!("Decryption failed"))?;

    Ok(Zeroizing::new(plaintext))
}

/// Create a verifier ciphertext for the given key
pub fn create_verifier(key: &SecretBox<[u8; 32]>) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = generate_nonce();
    let ciphertext = seal(key, &nonce, VERIFIER_PLAINTEXT, b"")?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Verify the derived key by decrypting the verifier
pub fn verify_key(key: &SecretBox<[u8; 32]>, nonce: &[u8], ciphertext: &[u8]) -> Result<()> {
    if nonce.len() != 24 {
        anyhow::bail!("Invalid nonce length");
    }
    let nonce_array: [u8; 24] = nonce.try_into()?;

    let plaintext = open(key, &nonce_array, ciphertext, b"")?;

    if plaintext.as_slice() == VERIFIER_PLAINTEXT {
        Ok(())
    } else {
        Err(anyhow!("Unlock failed"))
    }
}
