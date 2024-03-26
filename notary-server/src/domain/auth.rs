use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Structure of each whitelisted record of the API key whitelist for authorization purpose
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthorizationWhitelistRecord {
    pub name: String,
    pub api_key: String,
    pub created_at: String,
}

/// Convert whitelist data structure from vector to hashmap using api_key as the key to speed up lookup
pub fn authorization_whitelist_vec_into_hashmap(
    authorization_whitelist: Vec<AuthorizationWhitelistRecord>,
) -> HashMap<String, AuthorizationWhitelistRecord> {
    let mut hashmap = HashMap::new();
    authorization_whitelist.iter().for_each(|record| {
        hashmap.insert(record.api_key.clone(), record.to_owned());
    });
    hashmap
}
