use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use crate::open_id::{OAuthProviderClientConfig, OpenIdTokenResponse};

/// Common structure for OAuth user information
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuthUserInfo {
    /// Unique identifier for the user from the provider
    pub id: CompactString,
    /// User's email address (if available)
    pub email: Option<CompactString>,
    /// Whether the email is verified (if available)
    pub email_verified: Option<bool>,
    /// User's display name or full name (if available)
    pub name: Option<CompactString>,
    /// URL to the user's profile picture (if available)
    pub picture: Option<CompactString>,
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthUserInfoError {
    #[error("Failed to fetch user info: {0}")]
    FetchError(#[from] reqwest::Error),

    #[error("User info URL not provided")]
    NoUserInfoUrl,

    #[error("Failed to parse user info: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone)]
pub struct NormalOauthProvider {
    pub authorization_url: CompactString,
    pub token_url: CompactString,
    pub user_info_url: Option<CompactString>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NormalTokenResponse {
    pub access_token: CompactString,
    pub token_type: CompactString,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<CompactString>,
}

pub async fn oauth_normal_exchange_access_token(
    code: CompactString,
    constants: &NormalOauthProvider,
    client_config: &OAuthProviderClientConfig,
) -> Result<NormalTokenResponse, reqwest::Error> {
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
        .header("Accept", "application/json")
        .send()
        .await?
        .json::<NormalTokenResponse>()
        .await?;

    Ok(response)
}

#[derive(Debug, Clone)]
pub enum TokenExchangeResponse {
    OpenId(OpenIdTokenResponse),
    Normal(NormalTokenResponse),
}

impl TokenExchangeResponse {
    pub fn access_token(&self) -> &CompactString {
        match self {
            TokenExchangeResponse::OpenId(response) => &response.access_token,
            TokenExchangeResponse::Normal(response) => &response.access_token,
        }
    }
    pub fn refresh_token(&self) -> Option<&CompactString> {
        match self {
            TokenExchangeResponse::OpenId(response) => response.refresh_token.as_ref(),
            TokenExchangeResponse::Normal(response) => response.refresh_token.as_ref(),
        }
    }
}

