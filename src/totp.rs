use super::hotp;
use std::time::SystemTime;
use fast32::base32;
use rand::Rng;

/// The default period of TOTP code in seconds
pub const RFC6238_TOTP_PERIOD: u64 = 30;

/// The default length of TOTP secret in bytes
pub const RFC6238_TOTP_KEY_LENGTH: usize = 20;

/// TOTP secret
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSecret(Box<[u8]>);

impl AsRef<[u8]> for TotpSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TotpSecret {
    /// Create a new TOTP secret from a byte array
    pub fn new(secret: &[u8]) -> Self {
        Self(secret.into())
    }
    
    /// Create a new TOTP secret that complies with RFC 6238
    pub fn new_rfc6238() -> Self {
        let mut secret = [0u8; RFC6238_TOTP_KEY_LENGTH];
        rand::rng().fill(&mut secret);
        Self(secret.into())
    }

    /// Create a new TOTP secret from a base32 encoded string
    pub fn try_from_base32(secret: impl AsRef<str>) -> Result<Self, fast32::DecodeError> {
        let secret = base32::RFC4648_NOPAD
            .decode_str(secret.as_ref())?
            .into_boxed_slice();
        Ok(Self(secret))
    }

    /// Generate a TOTP code at the given timestamp
    pub fn generate(&self, period: u64, timestamp: SystemTime) -> u32 {
        // SAFE: The timestamp is always after the UNIX epoch.
        #[allow(clippy::unwrap_used)]
        let timestamp = timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
        
        let counter = timestamp / period as i64;
        hotp::HotpSecret::new(&self.0).generate(counter as u64)
    }
    
    /// Verify a TOTP code at the given timestamp
    /// 
    /// - `code`: the code to be verified
    /// - `period`: the period of the TOTP code in seconds
    /// - `timestamp`: the timestamp of the TOTP code
    /// - `back_retry`: will try to verify the code from `timestamp/period - back_retry` to `timestamp/period`
    pub fn verify(
        &self,
        code: u32,
        period: u64,
        timestamp: SystemTime,
        back_retry: usize,
    ) -> bool {
        if code > 999_999 {
            return false;
        }
        
        // SAFE: The timestamp is always after the UNIX epoch.
        #[allow(clippy::unwrap_used)]
        let timestamp = timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as i64;
        let counter = timestamp / period as i64;
        for i in 0..=back_retry {
            if hotp::HotpSecret::new(&self.0).verify(code, (counter - i as i64) as u64) {
                return true;
            }
        }
        false
    }
    
    /// Generate a URI for the TOTP secret
    pub fn to_uri(&self, label: impl AsRef<str>, issuer: impl AsRef<str>) -> String {
        format!(
            "otpauth://totp/{}?secret={}&issuer={}",
            label.as_ref(),
            base32::RFC4648_NOPAD.encode(&self.0),
            issuer.as_ref()
        )
    }
}