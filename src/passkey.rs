use std::cmp::PartialEq;
use fast32::base64;
use rand::Rng;
use ring::signature;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Challenge for passkey
pub struct PasskeyChallenge(pub Box<[u8]>);

impl AsRef<[u8]> for PasskeyChallenge {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Default passkey challenge size
pub const DEFAULT_PASSKEY_CHALLENGE_SIZE: usize = 32;

impl PasskeyChallenge {
    /// Generate a random challenge
    pub fn generate<const N: usize>() -> Self {
        let mut challenge = [0u8; N];
        rand::rng().fill(&mut challenge);
        Self(challenge.into())
    }
    
    /// Generate a random challenge with a custom rng
    pub fn generate_with_rng<const N: usize>(rng: &mut impl Rng) -> Self {
        let mut challenge = [0u8; N];
        rng.fill(&mut challenge);
        Self(challenge.into())
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
/// Public key for passkey
pub struct PasskeyPublicKey(pub Box<[u8]>);

/// Client data JSON of passkey. The schema is defined in [WebAuthn](https://www.w3.org/TR/webauthn-2/#dictionary-client-data)
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyClientData {
    #[serde(
        serialize_with = "serialize_client_data_challenge",
        deserialize_with = "deserialize_client_data_challenge"
    )]
    pub challenge: Box<[u8]>,
    pub origin: String,
    pub r#type: PasskeyChallengeType,
    pub cross_origin: Option<bool>,
    pub token_binding: Option<PasskeyTokenBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Refer to [WebAuthn](https://www.w3.org/TR/webauthn-2/#dictdef-tokenbinding)
pub struct PasskeyTokenBinding {
    pub status: PasskeyTokenBindingStatus,
    pub id: Option<Box<[u8]>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
/// Defined in [WebAuthn](https://www.w3.org/TR/webauthn-2/#enumdef-tokenbindingstatus)
pub enum PasskeyTokenBindingStatus {
    Present,
    Supported,
}

fn serialize_client_data_challenge<S>(value: &Box<[u8]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::RFC4648_URL_NOPAD.encode(value))
}

fn deserialize_client_data_challenge<'de, D>(deserializer: D) -> Result<Box<[u8]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    base64::RFC4648_URL_NOPAD
        .decode_str(&s)
        .map_err(serde::de::Error::custom)
        .map(Into::into)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Challenge type for passkey
pub enum PasskeyChallengeType {
    #[serde(rename = "webauthn.create")]
    /// Register a new passkey
    Create,
    
    #[serde(rename = "webauthn.get")]
    /// Authenticate with a passkey
    Get
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A completed passkey challenge
pub struct CompletedPasskeyChallenge {
    /// The user's credential ID
    pub credential_id: Box<[u8]>,
    
    /// The client data JSON. Will be deserialized into [PasskeyClientData]
    pub client_data_json: String,
    
    /// The user's signature of the challenge
    pub signature: Box<[u8]>,
}

/// Error type for passkey verification
#[derive(Debug, thiserror::Error)]
pub enum PasskeyVerificationError {
    /// Failed to deserialize client data JSON
    #[error("Failed to deserialize client data JSON: {0}")]
    ClientDataDeserializationError(#[from] serde_json::Error),
    /// Challenge mismatch
    #[error("Challenge mismatch")]
    ChallengeMismatch,
    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,
    /// Invalid public key format
    #[error("Invalid public key format")]
    InvalidPublicKey,
}


impl CompletedPasskeyChallenge {
    /// Verify the challenge
    pub fn verify(
        &self,
        expected_challenge: &PasskeyChallenge,
        public_key: &PasskeyPublicKey,
    ) -> Result<(), PasskeyVerificationError> {
        let client_data: PasskeyClientData =
            serde_json::from_str(&self.client_data_json)?;
        if expected_challenge.as_ref() != client_data.challenge.as_ref() {
            return Err(PasskeyVerificationError::ChallengeMismatch);
        }
        
        // create a verification key from the public key
        let verification_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &public_key.0);

        // Hash the client data JSON
        let client_data_hash = ring::digest::digest(
            &ring::digest::SHA256,
            self.client_data_json.as_bytes(),
        );
        
        verification_key
            .verify(client_data_hash.as_ref(), &self.signature)
            .map_err(|_| PasskeyVerificationError::InvalidSignature)
    }
}