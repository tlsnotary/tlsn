use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tlsn_core::CryptoProvider;
use tokio::sync::Semaphore;

#[cfg(feature = "tee_quote")]
use crate::tee::Quote;
use crate::{auth::AuthorizationMode, config::{NotarizationProperties, PluginProperties}};

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
    /// List of plugins that are loaded
    pub plugin_names: Vec<String>,
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
#[derive(Clone)]
pub struct NotaryGlobals {
    pub crypto_provider: Arc<CryptoProvider>,
    pub notarization_config: NotarizationProperties,
    pub plugin_config: PluginProperties,
    pub plugin_names: Arc<Vec<String>>,
    /// A temporary storage to store session_id and name of plugin requested
    pub store: Arc<Mutex<HashMap<String, String>>>,
    /// Selected authorization mode if any
    pub authorization_mode: Option<AuthorizationMode>,
    /// A semaphore to acquire a permit for notarization
    pub semaphore: Arc<Semaphore>,
}

impl NotaryGlobals {
    pub fn new(
        crypto_provider: Arc<CryptoProvider>,
        notarization_config: NotarizationProperties,
        plugin_config: PluginProperties,
        plugin_names: Arc<Vec<String>>,
        authorization_mode: Option<AuthorizationMode>,
        semaphore: Arc<Semaphore>,
    ) -> Self {
        Self {
            crypto_provider,
            notarization_config,
            plugin_config,
            plugin_names,
            store: Default::default(),
            authorization_mode,
            semaphore,
        }
    }
}
