#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../README.md")]

/// Password hashing and verification
pub mod password;

/// Passkey challenge generation and verification
pub mod passkey;

/// HOTP (HMAC-based One-Time Password) generation and verification
pub mod hotp;

/// TOTP (Time-based One-Time Password) generation and verification
pub mod totp;

/// OpenID Connect
pub mod open_id;

/// OAuth 2.0
pub mod oauth;

/// Email account verification
pub mod email_account;

/// JSON Web Tokens
pub mod jwt;
