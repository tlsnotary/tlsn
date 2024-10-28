pub mod auth;
pub mod cli;
pub mod notary;
#[cfg(feature = "tee_quote")]
use crate::tee::Quote;
use serde::{Deserialize, Serialize};

/// Response object of the /info API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    /// Current version of notary-server
    pub version: String,
    /// Public key of the notary signing key
    pub public_key: String,
    /// Current git commit hash of notary-server
    pub git_commit_hash: String,
    /// Hardware attestation
    #[cfg(feature = "tee_quote")]
    pub quote: Quote,
}
