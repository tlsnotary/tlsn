pub mod auth;
pub mod cli;
pub mod notary;

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
    /// Current git commit timestamp of notary-server
    pub git_commit_timestamp: String,
}
