use fast32::base32;
use ring::hmac;

/// HOTP secret
pub struct HotpSecret(Box<[u8]>);

impl AsRef<[u8]> for HotpSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl HotpSecret {
    /// Create a new HOTP secret from a byte array
    pub fn new(secret: &[u8]) -> Self {
        Self(secret.into())
    }

    /// Create a new HOTP secret from a base32 encoded string
    pub fn try_from_base32(secret: impl AsRef<str>) -> Result<Self, fast32::DecodeError> {
        let secret = base32::RFC4648_NOPAD
            .decode_str(secret.as_ref())?
            .into_boxed_slice();
        Ok(Self(secret))
    }

    /// Generate a HOTP code
    ///
    /// - `counter`: the counter value
    pub fn generate(&self, counter: u64) -> u32 {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        let wtr = counter.to_be_bytes();
        let signature = hmac::sign(&key, &wtr);
        let signature = signature.as_ref();
        let offset = signature[signature.len() - 1] & 0x0f;
        let mut code = ((signature[offset as usize] & 0x7f) as u32) << 24
            | (signature[offset as usize + 1] as u32) << 16
            | (signature[offset as usize + 2] as u32) << 8
            | signature[offset as usize + 3] as u32;
        code %= 1_000_000;
        code
    }

    /// valid a HOTP code
    ///
    /// - `code`: the code to be verified
    /// - `last`, `trials`: guess HOTP code from `last + 1` to `last + trials + 1`
    pub fn verify(&self, code: u32, count: u64) -> bool {
        if code > 999_999 {
            return false;
        }
        self.generate(count) == code
    }

    /// Generate a URI for the HOTP secret
    pub fn to_uri(&self, label: impl AsRef<str>, issuer: impl AsRef<str>) -> String {
        format!(
            "otpauth://hotp/{}?secret={}&issuer={}",
            label.as_ref(),
            base32::RFC4648_NOPAD.encode(&self.0),
            issuer.as_ref()
        )
    }
}