use std::fmt;
use thiserror::Error;

/// Domain validation errors
#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Service name cannot be empty")]
    EmptyService,
    #[error("Service name too long (max 255 characters)")]
    ServiceTooLong,
    #[error("Username cannot be empty")]
    EmptyUsername,
    #[error("Username too long (max 255 characters)")]
    UsernameTooLong,
    #[error("Password cannot be empty")]
    EmptyPassword,
    #[error("Password too long (max 1024 characters)")]
    PasswordTooLong,
    #[error("Notes too long (max 4096 characters)")]
    NotesTooLong,
    #[error("KDF salt must be exactly 16 bytes")]
    InvalidSaltLength,
    #[error("Verifier nonce must be exactly 24 bytes")]
    InvalidVerifierNonceLength,
    #[error("Verifier ciphertext cannot be empty")]
    EmptyVerifierCiphertext,
}

/// Service name (validated, non-empty, max 255 chars)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service(String);

impl Service {
    const MAX_LENGTH: usize = 255;

    pub fn try_parse(value: String) -> Result<Self, DomainError> {
        if value.is_empty() {
            return Err(DomainError::EmptyService);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(DomainError::ServiceTooLong);
        }
        Ok(Self(value))
    }

    pub fn as_ref(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Service {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Username (validated, non-empty, max 255 chars)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Username(String);

impl Username {
    const MAX_LENGTH: usize = 255;

    pub fn try_parse(value: String) -> Result<Self, DomainError> {
        if value.is_empty() {
            return Err(DomainError::EmptyUsername);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(DomainError::UsernameTooLong);
        }
        Ok(Self(value))
    }

    pub fn as_ref(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Password (validated, non-empty, max 1024 chars)
#[derive(Debug, Clone)]
pub struct Password(String);

impl Password {
    const MAX_LENGTH: usize = 1024;

    pub fn try_parse(value: String) -> Result<Self, DomainError> {
        if value.is_empty() {
            return Err(DomainError::EmptyPassword);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(DomainError::PasswordTooLong);
        }
        Ok(Self(value))
    }

    pub fn as_ref(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "********") // Never display actual password
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Notes (optional, max 4096 chars)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notes(String);

impl Notes {
    const MAX_LENGTH: usize = 4096;

    pub fn try_parse(value: String) -> Result<Self, DomainError> {
        if value.len() > Self::MAX_LENGTH {
            return Err(DomainError::NotesTooLong);
        }
        Ok(Self(value))
    }

    pub fn as_ref(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for Notes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Notes {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// KDF Salt (exactly 16 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfSalt([u8; 16]);

impl KdfSalt {
    pub fn try_parse(value: Vec<u8>) -> Result<Self, DomainError> {
        if value.len() != 16 {
            return Err(DomainError::InvalidSaltLength);
        }
        let mut array = [0u8; 16];
        array.copy_from_slice(&value);
        Ok(Self(array))
    }

    pub fn from_array(array: [u8; 16]) -> Self {
        Self(array)
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn into_inner(self) -> [u8; 16] {
        self.0
    }
}

impl AsRef<[u8]> for KdfSalt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Verifier Nonce (exactly 24 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierNonce([u8; 24]);

impl VerifierNonce {
    pub fn try_parse(value: Vec<u8>) -> Result<Self, DomainError> {
        if value.len() != 24 {
            return Err(DomainError::InvalidVerifierNonceLength);
        }
        let mut array = [0u8; 24];
        array.copy_from_slice(&value);
        Ok(Self(array))
    }

    pub fn from_array(array: [u8; 24]) -> Self {
        Self(array)
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn into_inner(self) -> [u8; 24] {
        self.0
    }
}

impl AsRef<[u8]> for VerifierNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Verifier Ciphertext (variable length, non-empty)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierCiphertext(Vec<u8>);

impl VerifierCiphertext {
    pub fn try_parse(value: Vec<u8>) -> Result<Self, DomainError> {
        if value.is_empty() {
            return Err(DomainError::EmptyVerifierCiphertext);
        }
        Ok(Self(value))
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for VerifierCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Entry Nonce (exactly 24 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryNonce([u8; 24]);

impl EntryNonce {
    pub fn try_parse(value: Vec<u8>) -> Result<Self, DomainError> {
        if value.len() != 24 {
            return Err(DomainError::InvalidVerifierNonceLength);
        }
        let mut array = [0u8; 24];
        array.copy_from_slice(&value);
        Ok(Self(array))
    }

    pub fn from_array(array: [u8; 24]) -> Self {
        Self(array)
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn into_inner(self) -> [u8; 24] {
        self.0
    }
}

impl AsRef<[u8]> for EntryNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Entry Ciphertext (variable length, non-empty)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCiphertext(Vec<u8>);

impl EntryCiphertext {
    pub fn try_parse(value: Vec<u8>) -> Result<Self, DomainError> {
        if value.is_empty() {
            return Err(DomainError::EmptyVerifierCiphertext);
        }
        Ok(Self(value))
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for EntryCiphertext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_validation() {
        assert!(Service::try_parse("github".to_string()).is_ok());
        assert!(Service::try_parse("".to_string()).is_err());
        assert!(Service::try_parse("a".repeat(256)).is_err());
    }

    #[test]
    fn test_username_validation() {
        assert!(Username::try_parse("alice".to_string()).is_ok());
        assert!(Username::try_parse("".to_string()).is_err());
        assert!(Username::try_parse("a".repeat(256)).is_err());
    }

    #[test]
    fn test_password_validation() {
        assert!(Password::try_parse("secret123".to_string()).is_ok());
        assert!(Password::try_parse("".to_string()).is_err());
        assert!(Password::try_parse("a".repeat(1025)).is_err());
    }

    #[test]
    fn test_notes_validation() {
        assert!(Notes::try_parse("Some notes".to_string()).is_ok());
        assert!(Notes::try_parse("".to_string()).is_ok()); // Empty is ok
        assert!(Notes::try_parse("a".repeat(4097)).is_err());
    }

    #[test]
    fn test_kdf_salt_validation() {
        assert!(KdfSalt::try_parse(vec![0u8; 16]).is_ok());
        assert!(KdfSalt::try_parse(vec![0u8; 15]).is_err());
        assert!(KdfSalt::try_parse(vec![0u8; 17]).is_err());
    }

    #[test]
    fn test_verifier_nonce_validation() {
        assert!(VerifierNonce::try_parse(vec![0u8; 24]).is_ok());
        assert!(VerifierNonce::try_parse(vec![0u8; 23]).is_err());
        assert!(VerifierNonce::try_parse(vec![0u8; 25]).is_err());
    }
}
