use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tlsn_core::CryptoProvider;
use tokio::sync::Semaphore;

#[cfg(feature = "tee_quote")]
use crate::tee::Quote;
use crate::{auth::AuthorizationWhitelistRecord, config::NotarizationProperties};

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

/// Request query of the /notarize API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationRequestQuery {
    /// Session id that is returned from /session API
    pub session_id: String,
}

/// Global data that needs to be shared with the axum handlers
#[derive(Clone, Debug)]
pub struct NotaryGlobals {
    pub crypto_provider: Arc<CryptoProvider>,
    pub notarization_config: NotarizationProperties,
    /// A temporary storage to store session_id
    pub store: Arc<Mutex<HashMap<String, ()>>>,
    /// Whitelist of API keys for authorization purpose
    pub authorization_whitelist: Option<Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>>,
    /// A semaphore to acquire a permit for notarization
    pub semaphore: Arc<Semaphore>,
}

impl NotaryGlobals {
    pub fn new(
        crypto_provider: Arc<CryptoProvider>,
        notarization_config: NotarizationProperties,
        authorization_whitelist: Option<Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>>,
        semaphore: Arc<Semaphore>,
    ) -> Self {
        Self {
            crypto_provider,
            notarization_config,
            store: Default::default(),
            authorization_whitelist,
            semaphore,
        }
    }
}
