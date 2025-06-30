use compact_str::CompactString;
use jsonwebtoken::{decode_header, DecodingKey};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct IdTokenClaims {
    pub iss: CompactString,
    pub sub: CompactString,
    pub aud: CompactString,
    pub exp: u64,
    pub iat: u64,
    pub email: Option<CompactString>,
    pub email_verified: Option<bool>,
    pub name: Option<CompactString>,
    pub picture: Option<CompactString>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyIdTokenError {
    #[error("Failed to decode header: {0}")]
    HeaderDecodingError(jsonwebtoken::errors::Error),
    #[error("Failed to decode component: {0}")]
    ComponentDecodingError(jsonwebtoken::errors::Error),
    #[error("Missing kid in header")]
    MissingKidInHeader,
    #[error("Failed to decode claims: {0}")]
    ClaimsDecodingError(jsonwebtoken::errors::Error),
    #[error("JWK not found for kid: {0}")]
    JwkNotFound(String),
}

pub fn get_id_token_kid(id_token: impl AsRef<str>) -> Result<String, VerifyIdTokenError> {
    let header =
        decode_header(id_token.as_ref()).map_err(VerifyIdTokenError::HeaderDecodingError)?;
    let kid = header.kid.ok_or(VerifyIdTokenError::MissingKidInHeader)?;
    Ok(kid)
}

pub fn verify_id_token_kid_unchecked(
    id_token: &str,
    expected_issuer: &str,
    expected_audience: &str,
    jwk: &Jwk,
) -> Result<IdTokenClaims, VerifyIdTokenError> {
    let decoding_key = match &jwk.algorithm {
        AlgorithmParameters::RSA(rsy_params) => {
            DecodingKey::from_rsa_components(&rsy_params.n, &rsy_params.e)
        }
        AlgorithmParameters::EllipticCurve(ec_params) => {
            DecodingKey::from_ec_components(&ec_params.x, &ec_params.y)
        }
        _ => unimplemented!("Unsupported JWK algorithm"),
    }
        .map_err(VerifyIdTokenError::ComponentDecodingError)?;

    let alg = jwk.common.key_algorithm.unwrap_or(KeyAlgorithm::RS256);
    let alg = match alg {
        KeyAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
        KeyAlgorithm::RS384 => jsonwebtoken::Algorithm::RS384,
        KeyAlgorithm::RS512 => jsonwebtoken::Algorithm::RS512,
        KeyAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
        KeyAlgorithm::ES384 => jsonwebtoken::Algorithm::ES384,
        _ => unimplemented!("Unsupported JWK key algorithm"),
    };

    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.set_audience(&[expected_audience]);
    validation.set_issuer(&[expected_issuer]);

    let claims = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(VerifyIdTokenError::ClaimsDecodingError)?;

    Ok(claims.claims)
}

#[derive(Debug, thiserror::Error)]
pub enum FetchJwkError {
    #[error("Failed to fetch JWK: {0}")]
    FetchError(#[from] reqwest::Error),
    #[error("Failed to decode JWK: {0}")]
    JwkDecodingError(reqwest::Error),
}

/// Fetch JWK from specified url
pub async fn fetch_jwk(url: impl AsRef<str>) -> Result<JwkSet, FetchJwkError> {
    let jwk = reqwest::get(url.as_ref())
        .await
        .map_err(FetchJwkError::FetchError)?
        .json::<JwkSet>()
        .await
        .map_err(FetchJwkError::JwkDecodingError)?;
    Ok(jwk)
}

pub fn verify_id_token(
    id_token: &str,
    config: &OAuthProviderClientConfig,
    provider: &OpenIdProvider,
    jwks: &JwkSet, // Assume this is already fetched & parsed
) -> Result<IdTokenClaims, VerifyIdTokenError> {
    let kid = get_id_token_kid(id_token)?;

    // Find matching JWK by kid
    let jwk = jwks
        .keys
        .iter()
        .find(|jwk| {
            if let Some(kid_value) = &jwk.common.key_id {
                kid_value == &kid
            } else {
                false
            }
        })
        .ok_or_else(|| VerifyIdTokenError::JwkNotFound(kid.clone()))?;

    verify_id_token_kid_unchecked(id_token, &provider.open_id_issuer, &config.client_id, jwk)
}

#[derive(Debug, Clone)]
pub struct OAuthProviderClientConfig {
    pub client_id: CompactString,
    pub client_secret: CompactString,
    pub redirect_uri: CompactString,
    pub scopes: Vec<CompactString>,
}

#[derive(Debug, Clone)]
pub struct OpenIdProvider {
    pub authorization_url: CompactString,
    pub token_url: CompactString,
    pub open_id_issuer: CompactString,
    pub open_id_jwks_url: CompactString,
    pub user_info_url: Option<CompactString>,
}