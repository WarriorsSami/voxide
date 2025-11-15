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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_determinism() {
        // Same password and salt should produce same key
        let password = SecretString::new("test_password_123".to_string().into_boxed_str());
        let salt = Salt::new([42u8; 16]);
        let params = KdfParams::default();

        let key1 = derive_key(&password, &salt, &params).expect("derive_key failed");
        let key2 = derive_key(&password, &salt, &params).expect("derive_key failed");

        assert_eq!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_derive_key_different_passwords() {
        // Different passwords should produce different keys
        let password1 = SecretString::new("password1".to_string().into_boxed_str());
        let password2 = SecretString::new("password2".to_string().into_boxed_str());
        let salt = Salt::new([1u8; 16]);
        let params = KdfParams::default();

        let key1 = derive_key(&password1, &salt, &params).expect("derive_key failed");
        let key2 = derive_key(&password2, &salt, &params).expect("derive_key failed");

        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_derive_key_different_salts() {
        // Same password but different salts should produce different keys
        let password = SecretString::new("test_password".to_string().into_boxed_str());
        let salt1 = Salt::new([1u8; 16]);
        let salt2 = Salt::new([2u8; 16]);
        let params = KdfParams::default();

        let key1 = derive_key(&password, &salt1, &params).expect("derive_key failed");
        let key2 = derive_key(&password, &salt2, &params).expect("derive_key failed");

        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_aead_seal_open_roundtrip() {
        // Encrypt and decrypt should produce original plaintext
        let password = SecretString::new("master_password".to_string().into_boxed_str());
        let salt = Salt::new([99u8; 16]);
        let params = KdfParams::default();
        let key = derive_key(&password, &salt, &params).expect("derive_key failed");

        let plaintext = b"secret data to encrypt";
        let nonce = Nonce::new([7u8; 24]);
        let ad = ad_for("github", "user@example.com");

        // Encrypt
        let ciphertext = seal(&key, &nonce, plaintext, &ad).expect("seal failed");

        // Decrypt
        let decrypted = open(&key, &nonce, &ciphertext, &ad).expect("open failed");

        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn test_aead_tamper_ciphertext() {
        // Tampering with ciphertext should cause decryption to fail
        let password = SecretString::new("master_password".to_string().into_boxed_str());
        let salt = Salt::new([88u8; 16]);
        let params = KdfParams::default();
        let key = derive_key(&password, &salt, &params).expect("derive_key failed");

        let plaintext = b"sensitive information";
        let nonce = Nonce::new([3u8; 24]);
        let ad = ad_for("service", "username");

        let ciphertext = seal(&key, &nonce, plaintext, &ad).expect("seal failed");

        // Tamper with ciphertext by flipping a bit
        let mut tampered_bytes = ciphertext.as_bytes().to_vec();
        if !tampered_bytes.is_empty() {
            tampered_bytes[0] ^= 0x01;
        }
        let tampered_ciphertext = Ciphertext::new(tampered_bytes);

        // Decryption should fail
        let result = open(&key, &nonce, &tampered_ciphertext, &ad);
        assert!(matches!(result, Err(VaultError::DecryptFailed)));
    }

    #[test]
    fn test_aead_tamper_nonce() {
        // Using wrong nonce should cause decryption to fail
        let password = SecretString::new("master_password".to_string().into_boxed_str());
        let salt = Salt::new([77u8; 16]);
        let params = KdfParams::default();
        let key = derive_key(&password, &salt, &params).expect("derive_key failed");

        let plaintext = b"secret message";
        let nonce1 = Nonce::new([5u8; 24]);
        let nonce2 = Nonce::new([6u8; 24]); // Different nonce
        let ad = ad_for("service", "user");

        let ciphertext = seal(&key, &nonce1, plaintext, &ad).expect("seal failed");

        // Try to decrypt with wrong nonce
        let result = open(&key, &nonce2, &ciphertext, &ad);
        assert!(matches!(result, Err(VaultError::DecryptFailed)));
    }

    #[test]
    fn test_aead_tamper_associated_data() {
        // Using wrong AD should cause decryption to fail
        let password = SecretString::new("master_password".to_string().into_boxed_str());
        let salt = Salt::new([66u8; 16]);
        let params = KdfParams::default();
        let key = derive_key(&password, &salt, &params).expect("derive_key failed");

        let plaintext = b"confidential data";
        let nonce = Nonce::new([8u8; 24]);
        let ad1 = ad_for("github", "alice");
        let ad2 = ad_for("github", "bob"); // Different AD

        let ciphertext = seal(&key, &nonce, plaintext, &ad1).expect("seal failed");

        // Try to decrypt with wrong AD
        let result = open(&key, &nonce, &ciphertext, &ad2);
        assert!(matches!(result, Err(VaultError::DecryptFailed)));
    }

    #[test]
    fn test_aead_wrong_key() {
        // Using wrong key should cause decryption to fail
        let password1 = SecretString::new("password1".to_string().into_boxed_str());
        let password2 = SecretString::new("password2".to_string().into_boxed_str());
        let salt = Salt::new([55u8; 16]);
        let params = KdfParams::default();

        let key1 = derive_key(&password1, &salt, &params).expect("derive_key failed");
        let key2 = derive_key(&password2, &salt, &params).expect("derive_key failed");

        let plaintext = b"top secret";
        let nonce = Nonce::new([9u8; 24]);
        let ad = ad_for("service", "user");

        let ciphertext = seal(&key1, &nonce, plaintext, &ad).expect("seal failed");

        // Try to decrypt with wrong key
        let result = open(&key2, &nonce, &ciphertext, &ad);
        assert!(matches!(result, Err(VaultError::DecryptFailed)));
    }

    #[test]
    fn test_verifier_creation_and_validation() {
        // Create verifier and validate it succeeds with correct key
        let password = SecretString::new("verifier_test".to_string().into_boxed_str());
        let salt = Salt::new([33u8; 16]);
        let params = KdfParams::default();
        let key = derive_key(&password, &salt, &params).expect("derive_key failed");

        let (nonce, ciphertext) = create_verifier(&key).expect("create_verifier failed");

        // Verification should succeed
        verify_key(&key, &nonce, &ciphertext).expect("verify_key failed");
    }

    #[test]
    fn test_verifier_wrong_key() {
        // Verifier should fail with wrong key
        let password1 = SecretString::new("correct_password".to_string().into_boxed_str());
        let password2 = SecretString::new("wrong_password".to_string().into_boxed_str());
        let salt = Salt::new([44u8; 16]);
        let params = KdfParams::default();

        let key1 = derive_key(&password1, &salt, &params).expect("derive_key failed");
        let key2 = derive_key(&password2, &salt, &params).expect("derive_key failed");

        let (nonce, ciphertext) = create_verifier(&key1).expect("create_verifier failed");

        // Verification with wrong key should fail
        let result = verify_key(&key2, &nonce, &ciphertext);
        assert!(matches!(result, Err(VaultError::AuthFailed | VaultError::DecryptFailed)));
    }

    #[test]
    fn test_ad_for_encoding() {
        // Test AD encoding with length prefixes
        let ad = ad_for("github", "alice");
        let bytes = ad.as_bytes();

        // Should encode: [len(github)][github][len(alice)][alice]
        // 4 bytes for "github" length + 6 bytes "github" + 4 bytes for "alice" length + 5 bytes "alice"
        assert_eq!(bytes.len(), 4 + 6 + 4 + 5);

        // Check first length prefix (github = 6 bytes)
        assert_eq!(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), 6);
    }
}

