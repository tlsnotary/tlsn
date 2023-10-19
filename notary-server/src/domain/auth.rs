use serde::Deserialize;

/// Structure of each whitelisted record
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthorizationWhitelistRecord {
    pub name: String,
    pub api_key: String,
    pub created_at: String,
}
