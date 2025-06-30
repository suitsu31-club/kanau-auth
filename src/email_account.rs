use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use validator::ValidateEmail;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmailDomainConfig {
    pub enable_whitelist: bool,
    pub whitelist: Vec<CompactString>,
    pub enable_blacklist: bool,
    pub blacklist: Vec<CompactString>,
}

impl EmailDomainConfig {
    /// Check if the email is valid
    pub fn is_valid(&self, email: &str) -> bool {
        let is_email_address = email.validate_email();
        if !is_email_address {
            return false;
        }
        let Some(domain) = email.split('@').next_back() else {
            return false;
        };
        if self.enable_whitelist {
            return self.whitelist.contains(&domain.into());
        }
        if self.enable_blacklist {
            return !self.blacklist.contains(&domain.into());
        }
        true
    }
}