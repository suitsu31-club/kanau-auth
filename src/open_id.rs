//! OpenID Connect JWT token verification and validation.
//!
//! This module provides functionality for verifying OpenID Connect ID tokens using JSON Web Keys (JWK).
//! It supports RSA and Elliptic Curve cryptographic algorithms and handles the complete verification
//! process including signature validation, issuer verification, and audience validation.
//!
//! # Examples
//!
//! ```rust
//! use kanau_auth::open_id::{verify_id_token, fetch_jwk, OAuthProviderClientConfig, OpenIdProvider};
//! use compact_str::CompactString;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure OAuth provider
//! let config = OAuthProviderClientConfig {
//!     client_id: CompactString::new("your-client-id"),
//!     client_secret: CompactString::new("your-client-secret"),
//!     redirect_uri: CompactString::new("https://your-app.com/callback"),
//!     scopes: vec![CompactString::new("openid"), CompactString::new("email")],
//! };
//!
//! // Configure OpenID provider
//! let provider = OpenIdProvider {
//!     authorization_url: CompactString::new("https://provider.com/auth"),
//!     token_url: CompactString::new("https://provider.com/token"),
//!     open_id_issuer: CompactString::new("https://provider.com"),
//!     open_id_jwks_url: CompactString::new("https://provider.com/.well-known/jwks.json"),
//!     user_info_url: Some(CompactString::new("https://provider.com/userinfo")),
//! };
//!
//! // Fetch JWK set
//! let jwks = fetch_jwk(&provider.open_id_jwks_url).await?;
//!
//! // Verify ID token
//! let id_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...";
//! let claims = verify_id_token(id_token, &config, &provider, &jwks)?;
//!
//! println!("User: {} ({})", claims.name.unwrap_or_default(), claims.email.unwrap_or_default());
//! # Ok(())
//! # }
//! ```

use compact_str::CompactString;
use jsonwebtoken::{decode_header, DecodingKey};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm};
use serde::{Deserialize, Serialize};

/// Claims contained within an OpenID Connect ID token.
///
/// This struct represents the standard claims that can be found in an OpenID Connect ID token
/// as defined by the OpenID Connect Core specification. It includes both required claims
/// (iss, sub, aud, exp, iat) and optional claims commonly used for user identification.
///
/// # Fields
///
/// * `iss` - Issuer identifier, typically the URL of the OpenID provider
/// * `sub` - Subject identifier, a unique identifier for the user
/// * `aud` - Audience, the client ID that this token was issued for
/// * `exp` - Expiration time as a Unix timestamp
/// * `iat` - Issued at time as a Unix timestamp
/// * `email` - User's email address (optional)
/// * `email_verified` - Whether the email address has been verified (optional)
/// * `name` - User's full name (optional)
/// * `picture` - URL of the user's profile picture (optional)
///
/// # Examples
///
/// ```rust
/// use kanau_auth::open_id::IdTokenClaims;
/// use compact_str::CompactString;
///
/// let claims = IdTokenClaims {
///     iss: CompactString::new("https://accounts.google.com"),
///     sub: CompactString::new("1234567890"),
///     aud: CompactString::new("your-client-id"),
///     exp: 1234567890,
///     iat: 1234567800,
///     email: Some(CompactString::new("user@example.com")),
///     email_verified: Some(true),
///     name: Some(CompactString::new("John Doe")),
///     picture: Some(CompactString::new("https://example.com/avatar.jpg")),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct IdTokenClaims {
    /// Issuer identifier - the URL of the OpenID provider that issued this token
    pub iss: CompactString,
    /// Subject identifier - a unique identifier for the authenticated user
    pub sub: CompactString,
    /// Audience - the client ID that this token was issued for
    pub aud: CompactString,
    /// Expiration time as a Unix timestamp (seconds since epoch)
    pub exp: u64,
    /// Issued at time as a Unix timestamp (seconds since epoch)
    pub iat: u64,
    /// User's email address (optional)
    pub email: Option<CompactString>,
    /// Whether the email address has been verified by the provider (optional)
    pub email_verified: Option<bool>,
    /// User's full name (optional)
    pub name: Option<CompactString>,
    /// URL of the user's profile picture (optional)
    pub picture: Option<CompactString>,
}

/// Errors that can occur during ID token verification.
///
/// This enum represents all possible errors that can occur when verifying an OpenID Connect
/// ID token, from header parsing to final claims validation.
///
/// # Variants
///
/// * `HeaderDecodingError` - Failed to decode the JWT header
/// * `ComponentDecodingError` - Failed to decode cryptographic components from JWK
/// * `MissingKidInHeader` - The JWT header is missing the required "kid" (key ID) field
/// * `ClaimsDecodingError` - Failed to decode or validate the JWT claims
/// * `JwkNotFound` - No matching JWK was found for the specified key ID
#[derive(Debug, thiserror::Error)]
pub enum VerifyIdTokenError {
    /// Failed to decode the JWT header
    #[error("Failed to decode header: {0}")]
    HeaderDecodingError(jsonwebtoken::errors::Error),
    /// Failed to decode cryptographic components from the JWK
    #[error("Failed to decode component: {0}")]
    ComponentDecodingError(jsonwebtoken::errors::Error),
    /// The JWT header is missing the required "kid" (key ID) field
    #[error("Missing kid in header")]
    MissingKidInHeader,
    /// Failed to decode or validate the JWT claims (signature, expiration, etc.)
    #[error("Failed to decode claims: {0}")]
    ClaimsDecodingError(jsonwebtoken::errors::Error),
    /// No matching JWK was found for the specified key ID
    #[error("JWK not found for kid: {0}")]
    JwkNotFound(String),
}

/// Extracts the key ID (kid) from an ID token's header.
///
/// This function decodes the JWT header and extracts the "kid" (key identifier) field,
/// which is used to identify which key from the JWK set should be used to verify the token.
///
/// # Arguments
///
/// * `id_token` - The JWT ID token as a string
///
/// # Returns
///
/// Returns the key ID as a `String` on success, or a `VerifyIdTokenError` if:
/// - The header cannot be decoded
/// - The header is missing the "kid" field
///
/// # Examples
///
/// ```rust
/// use kanau_auth::open_id::get_id_token_kid;
///
/// let id_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0...";
/// let kid = get_id_token_kid(id_token)?;
/// assert_eq!(kid, "test-key-id");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn get_id_token_kid(id_token: impl AsRef<str>) -> Result<String, VerifyIdTokenError> {
    let header =
        decode_header(id_token.as_ref()).map_err(VerifyIdTokenError::HeaderDecodingError)?;
    let kid = header.kid.ok_or(VerifyIdTokenError::MissingKidInHeader)?;
    Ok(kid)
}

/// Verifies an ID token using a specific JWK without checking the key ID.
///
/// This function performs the complete verification of an OpenID Connect ID token using
/// the provided JWK. It validates the signature, issuer, audience, and expiration time.
/// This is a lower-level function that assumes you have already selected the correct JWK.
///
/// # Arguments
///
/// * `id_token` - The JWT ID token to verify
/// * `expected_issuer` - The expected issuer URL (must match the "iss" claim)
/// * `expected_audience` - The expected audience (must match the "aud" claim, typically your client ID)
/// * `jwk` - The JSON Web Key to use for signature verification
///
/// # Returns
///
/// Returns the decoded `IdTokenClaims` on successful verification, or a `VerifyIdTokenError` if:
/// - The JWK algorithm is unsupported
/// - The cryptographic components cannot be decoded
/// - The token signature is invalid
/// - The issuer or audience doesn't match
/// - The token has expired
///
/// # Security Note
///
/// This function does not verify that the JWK's key ID matches the token's "kid" header.
/// Use `verify_id_token` for complete verification including key ID matching.
///
/// # Examples
///
/// ```rust
/// use kanau_auth::open_id::verify_id_token_kid_unchecked;
/// use jsonwebtoken::jwk::Jwk;
///
/// # fn example(id_token: &str, jwk: &Jwk) -> Result<(), Box<dyn std::error::Error>> {
/// let claims = verify_id_token_kid_unchecked(
///     id_token,
///     "https://accounts.google.com",
///     "your-client-id",
///     jwk
/// )?;
///
/// println!("Token verified for user: {}", claims.sub);
/// # Ok(())
/// # }
/// ```
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

/// Errors that can occur when fetching JWK sets from a remote endpoint.
///
/// This enum represents errors that can occur during the HTTP request to fetch
/// a JWK set from an OpenID provider's JWKS endpoint.
///
/// # Variants
///
/// * `FetchError` - Network or HTTP error during the request
/// * `JwkDecodingError` - Error parsing the JSON response into a JWK set
#[derive(Debug, thiserror::Error)]
pub enum FetchJwkError {
    /// Network or HTTP error occurred while fetching the JWK set
    #[error("Failed to fetch JWK: {0}")]
    FetchError(#[from] reqwest::Error),
    /// Failed to parse the JSON response into a valid JWK set
    #[error("Failed to decode JWK: {0}")]
    JwkDecodingError(reqwest::Error),
}

/// Fetches a JWK set from the specified URL.
///
/// This function makes an HTTP GET request to the provided URL and attempts to parse
/// the response as a JSON Web Key Set (JWKS). This is typically used to fetch the
/// public keys from an OpenID provider's JWKS endpoint.
///
/// # Arguments
///
/// * `url` - The URL of the JWKS endpoint (e.g., "https://provider.com/.well-known/jwks.json")
///
/// # Returns
///
/// Returns a `JwkSet` containing the public keys on success, or a `FetchJwkError` if:
/// - The HTTP request fails (network error, 404, etc.)
/// - The response cannot be parsed as valid JSON
/// - The JSON doesn't conform to the JWK set format
///
/// # Examples
///
/// ```rust
/// use kanau_auth::open_id::fetch_jwk;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let jwks = fetch_jwk("https://www.googleapis.com/oauth2/v3/certs").await?;
/// println!("Fetched {} keys", jwks.keys.len());
/// # Ok(())
/// # }
/// ```
pub async fn fetch_jwk(url: impl AsRef<str>) -> Result<JwkSet, FetchJwkError> {
    let jwk = reqwest::get(url.as_ref())
        .await
        .map_err(FetchJwkError::FetchError)?
        .json::<JwkSet>()
        .await
        .map_err(FetchJwkError::JwkDecodingError)?;
    Ok(jwk)
}

/// Verifies an OpenID Connect ID token with complete validation.
///
/// This is the main function for verifying OpenID Connect ID tokens. It performs the complete
/// verification process including:
/// 1. Extracting the key ID from the token header
/// 2. Finding the matching JWK in the provided JWK set
/// 3. Verifying the token signature, issuer, audience, and expiration
///
/// # Arguments
///
/// * `id_token` - The JWT ID token to verify
/// * `config` - OAuth provider client configuration (contains client_id for audience validation)
/// * `provider` - OpenID provider configuration (contains issuer for validation)
/// * `jwks` - The JWK set containing the provider's public keys (should be fetched using `fetch_jwk`)
///
/// # Returns
///
/// Returns the decoded `IdTokenClaims` on successful verification, or a `VerifyIdTokenError` if:
/// - The token header cannot be decoded or is missing the "kid" field
/// - No matching JWK is found for the token's key ID
/// - The token signature is invalid
/// - The issuer doesn't match the provider's issuer
/// - The audience doesn't match the client ID
/// - The token has expired
///
/// # Examples
///
/// ```rust
/// use kanau_auth::open_id::{verify_id_token, fetch_jwk, OAuthProviderClientConfig, OpenIdProvider};
/// use compact_str::CompactString;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = OAuthProviderClientConfig {
///     client_id: CompactString::new("your-client-id"),
///     client_secret: CompactString::new("your-client-secret"),
///     redirect_uri: CompactString::new("https://your-app.com/callback"),
///     scopes: vec![CompactString::new("openid"), CompactString::new("email")],
/// };
///
/// let provider = OpenIdProvider {
///     authorization_url: CompactString::new("https://accounts.google.com/o/oauth2/v2/auth"),
///     token_url: CompactString::new("https://oauth2.googleapis.com/token"),
///     open_id_issuer: CompactString::new("https://accounts.google.com"),
///     open_id_jwks_url: CompactString::new("https://www.googleapis.com/oauth2/v3/certs"),
///     user_info_url: Some(CompactString::new("https://openidconnect.googleapis.com/v1/userinfo")),
/// };
///
/// let jwks = fetch_jwk(&provider.open_id_jwks_url).await?;
/// let id_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."; // Your actual ID token
/// let claims = verify_id_token(id_token, &config, &provider, &jwks)?;
///
/// println!("Verified token for user: {} ({})",
///          claims.name.unwrap_or_default(),
///          claims.email.unwrap_or_default());
/// # Ok(())
/// # }
/// ```
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

/// Configuration for an OAuth 2.0 / OpenID Connect client.
///
/// This struct contains the client-specific configuration needed to interact with
/// an OAuth 2.0 / OpenID Connect provider. These values are typically obtained
/// when registering your application with the provider.
///
/// # Fields
///
/// * `client_id` - The public identifier for your application
/// * `client_secret` - The secret key for your application (keep this secure)
/// * `redirect_uri` - The URI where the provider will redirect after authorization
/// * `scopes` - The list of permissions your application is requesting
///
/// # Examples
///
/// ```rust
/// use kanau_auth::open_id::OAuthProviderClientConfig;
/// use compact_str::CompactString;
///
/// let config = OAuthProviderClientConfig {
///     client_id: CompactString::new("123456789.apps.googleusercontent.com"),
///     client_secret: CompactString::new("your-client-secret"),
///     redirect_uri: CompactString::new("https://yourapp.com/auth/callback"),
///     scopes: vec![
///         CompactString::new("openid"),
///         CompactString::new("email"),
///         CompactString::new("profile"),
///     ],
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProviderClientConfig {
    /// The public identifier for your application, provided by the OAuth provider
    pub client_id: CompactString,
    /// The secret key for your application (keep this secure and never expose it publicly)
    pub client_secret: CompactString,
    /// The URI where the provider will redirect users after authorization
    pub redirect_uri: CompactString,
    /// The list of OAuth scopes (permissions) your application is requesting
    pub scopes: Vec<CompactString>,
}

/// Configuration for an OpenID Connect provider.
///
/// This struct contains the endpoint URLs and configuration needed to interact with
/// an OpenID Connect provider. These values are typically found in the provider's
/// OpenID Connect discovery document (usually at `/.well-known/openid_configuration`).
///
/// # Fields
///
/// * `authorization_url` - The authorization endpoint where users are redirected to log in
/// * `token_url` - The token endpoint where authorization codes are exchanged for tokens
/// * `open_id_issuer` - The issuer identifier used in ID tokens
/// * `open_id_jwks_url` - The JWKS endpoint containing the provider's public keys
/// * `user_info_url` - Optional endpoint for fetching additional user information
///
/// # Examples
///
/// ```rust
/// use kanau_auth::open_id::OpenIdProvider;
/// use compact_str::CompactString;
///
/// // Google OpenID Connect configuration
/// let google_provider = OpenIdProvider {
///     authorization_url: CompactString::new("https://accounts.google.com/o/oauth2/v2/auth"),
///     token_url: CompactString::new("https://oauth2.googleapis.com/token"),
///     open_id_issuer: CompactString::new("https://accounts.google.com"),
///     open_id_jwks_url: CompactString::new("https://www.googleapis.com/oauth2/v3/certs"),
///     user_info_url: Some(CompactString::new("https://openidconnect.googleapis.com/v1/userinfo")),
/// };
///
/// // Microsoft Azure AD configuration
/// let azure_provider = OpenIdProvider {
///     authorization_url: CompactString::new("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
///     token_url: CompactString::new("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
///     open_id_issuer: CompactString::new("https://login.microsoftonline.com/{tenant}/v2.0"),
///     open_id_jwks_url: CompactString::new("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
///     user_info_url: Some(CompactString::new("https://graph.microsoft.com/oidc/userinfo")),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct OpenIdProvider {
    /// The authorization endpoint where users are redirected to authenticate
    pub authorization_url: CompactString,
    /// The token endpoint where authorization codes are exchanged for access and ID tokens
    pub token_url: CompactString,
    /// The issuer identifier that appears in the "iss" claim of ID tokens
    pub open_id_issuer: CompactString,
    /// The JWKS endpoint containing the provider's public keys for token verification
    pub open_id_jwks_url: CompactString,
    /// Optional endpoint for fetching additional user profile information
    pub user_info_url: Option<CompactString>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenIdTokenResponse {
    pub access_token: CompactString,
    pub id_token: CompactString,
    pub token_type: CompactString,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<CompactString>,
}



pub async fn open_id_exchange_access_token(
    code: CompactString,
    constants: &OpenIdProvider,
    client_config: &OAuthProviderClientConfig,
) -> Result<OpenIdTokenResponse, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client
        .post(constants.token_url.as_str())
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("client_id", client_config.client_id.as_str()),
            ("client_secret", client_config.client_secret.as_str()),
            ("redirect_uri", client_config.redirect_uri.as_str()),
        ])
        .send()
        .await?
        .json::<OpenIdTokenResponse>()
        .await?;

    Ok(response)
}

