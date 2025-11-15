#![allow(dead_code)]

use secrecy::{ExposeSecret, SecretBox};
use std::fmt;
use zeroize::Zeroizing;

use crate::errors::{VaultError, VaultResult};

/// Type-safe wrapper for KDF salt (16 bytes)
#[derive(Clone)]
pub struct Salt([u8; 16]);

impl Salt {
    /// Create a new Salt from exactly 16 bytes
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Try to parse salt from a byte slice
    pub fn try_from_slice(slice: &[u8]) -> VaultResult<Self> {
        if slice.len() != 16 {
            return Err(VaultError::KdfFailed(format!(
                "Invalid salt length: expected 16 bytes, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the salt as a byte slice
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Convert to Vec<u8> for serialization
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Salt([redacted 16 bytes])")
    }
}

/// Type-safe wrapper for AEAD nonce (24 bytes for XChaCha20-Poly1305)
#[derive(Clone)]
pub struct Nonce([u8; 24]);

impl Nonce {
    /// Create a new Nonce from exactly 24 bytes
    pub fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Try to parse nonce from a byte slice
    pub fn try_from_slice(slice: &[u8]) -> VaultResult<Self> {
        if slice.len() != 24 {
            return Err(VaultError::InvalidNonce);
        }
        let mut bytes = [0u8; 24];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the nonce as a byte slice
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }

    /// Convert to Vec<u8> for serialization
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce([redacted 24 bytes])")
    }
}

/// Type-safe wrapper for derived encryption key (32 bytes)
/// This wraps SecretBox to ensure keys are zeroized on drop
pub struct EncryptionKey(SecretBox<[u8; 32]>);

impl EncryptionKey {
    /// Create a new EncryptionKey from a SecretBox
    pub fn new(key: SecretBox<[u8; 32]>) -> Self {
        Self(key)
    }

    /// Get the underlying SecretBox
    pub fn as_secret(&self) -> &SecretBox<[u8; 32]> {
        &self.0
    }

    /// Expose the secret key bytes (use with caution)
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptionKey([redacted 32 bytes])")
    }
}

/// Type-safe wrapper for ciphertext (encrypted data + authentication tag)
#[derive(Clone)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Create a new Ciphertext from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create from a byte slice
    pub fn from_slice(slice: &[u8]) -> Self {
        Self(slice.to_vec())
    }

    /// Get the ciphertext as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to Vec<u8> for serialization
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Get length of ciphertext
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if ciphertext is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext([{} bytes])", self.0.len())
    }
}

/// Type-safe wrapper for plaintext (automatically zeroized on drop)
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    /// Create a new Plaintext from zeroizing bytes
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// Get the plaintext as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Convert to Zeroizing<Vec<u8>>
    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext([redacted {} bytes])", self.0.len())
    }
}

/// Type-safe wrapper for Associated Data (AEAD context binding)
#[derive(Clone)]
pub struct AssociatedData(Vec<u8>);

impl AssociatedData {
    /// Create new AssociatedData from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create empty AssociatedData
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// Get the associated data as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for AssociatedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AssociatedData([{} bytes])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_creation() {
        let bytes = [42u8; 16];
        let salt = Salt::new(bytes);
        assert_eq!(salt.as_bytes(), &bytes);
    }

    #[test]
    fn test_salt_try_from_slice() {
        let bytes = vec![1u8; 16];
        let salt = Salt::try_from_slice(&bytes).unwrap();
        assert_eq!(salt.as_bytes()[0], 1);

        // Invalid length
        let invalid = vec![1u8; 15];
        assert!(Salt::try_from_slice(&invalid).is_err());
    }

    #[test]
    fn test_nonce_creation() {
        let bytes = [99u8; 24];
        let nonce = Nonce::new(bytes);
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn test_nonce_try_from_slice() {
        let bytes = vec![2u8; 24];
        let nonce = Nonce::try_from_slice(&bytes).unwrap();
        assert_eq!(nonce.as_bytes()[0], 2);

        // Invalid length
        let invalid = vec![2u8; 23];
        assert!(Nonce::try_from_slice(&invalid).is_err());
    }

    #[test]
    fn test_ciphertext() {
        let bytes = vec![3, 1, 4, 1, 5];
        let ct = Ciphertext::new(bytes.clone());
        assert_eq!(ct.as_bytes(), &bytes[..]);
        assert_eq!(ct.len(), 5);
        assert!(!ct.is_empty());
    }
}
