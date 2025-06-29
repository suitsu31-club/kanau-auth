use argon2::password_hash::SaltString;
use argon2::{PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;

/// Password hashing and verification
pub trait PasswordAlgorithm {
    /// Error type for password hashing and verification
    type Error;

    /// Hashes a password
    fn hash_password(&self, password: &str) -> Result<String, Self::Error>;
    
    /// Verifies a password
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Self::Error>;
}

/// Bcrypt password hashing and verification
#[derive(Debug, Clone, Copy)]
pub struct BcryptPasswordAlgorithm {
    /// Cost of the bcrypt algorithm
    pub cost: u32,
}

impl Default for BcryptPasswordAlgorithm {
    fn default() -> Self {
        Self {
            cost: bcrypt::DEFAULT_COST,
        }
    }
}

impl BcryptPasswordAlgorithm {
    /// Creates a new [BcryptPasswordAlgorithm] with the given cost
    pub fn new(cost: u32) -> Self {
        Self { cost }
    }
}

impl PasswordAlgorithm for BcryptPasswordAlgorithm {
    type Error = bcrypt::BcryptError;

    fn hash_password(&self, password: &str) -> Result<String, Self::Error> {
        bcrypt::hash(password, self.cost)
    }

    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Self::Error> {
        bcrypt::verify(password, hash)
    }
}

/// Argon2 password hashing and verification
#[derive(Debug, Clone, Default)]
pub struct Argon2PasswordAlgorithm<'a> {
    config: argon2::Argon2<'a>
}

impl<'a> Argon2PasswordAlgorithm<'a> {
    /// Creates a new [Argon2PasswordAlgorithm] with the given config
    pub fn new(config: argon2::Argon2<'a>) -> Self {
        Self { config }
    }
}

impl<'a> PasswordAlgorithm for Argon2PasswordAlgorithm<'a> {
    type Error = argon2::password_hash::Error;

    fn hash_password(&self, password: &str) -> Result<String, Self::Error> {
        let salt = SaltString::generate(&mut OsRng);
        self.config.hash_password(password.as_bytes(), &salt).map(|hash| hash.to_string())
    }

    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Self::Error> {
        let parsed_hash = PasswordHash::new(hash)?;
        self.config.verify_password(password.as_bytes(), &parsed_hash).map(|_| true)
    }
}
