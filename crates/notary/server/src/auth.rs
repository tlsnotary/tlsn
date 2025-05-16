pub(crate) mod jwt;
pub(crate) mod whitelist;

use eyre::{eyre, Result};
use jwt::load_jwt_key;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tracing::debug;
use whitelist::load_authorization_whitelist;

pub use jwt::{Jwt, JwtError};
pub use whitelist::{watch_and_reload_authorization_whitelist, AuthorizationWhitelistRecord};

use crate::{AuthorizationModeProperties, NotaryServerProperties};

/// Supported authorization modes.
#[derive(Clone)]
pub enum AuthorizationMode {
    Jwt(Jwt),
    Whitelist(Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>),
}

impl AuthorizationMode {
    pub fn as_whitelist(
        &self,
    ) -> Option<Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>> {
        match self {
            Self::Jwt(..) => None,
            Self::Whitelist(whitelist) => Some(whitelist.clone()),
        }
    }
}

/// Load authorization mode if it is enabled
pub async fn load_authorization_mode(
    config: &NotaryServerProperties,
) -> Result<Option<AuthorizationMode>> {
    if !config.auth.enabled {
        debug!("Skipping authorization as it is turned off.");
        return Ok(None);
    }

    let auth_mode = match config.auth.mode.as_ref().ok_or_else(|| {
        eyre!(
            "Authorization enabled but neither whitelist nor jwt properties provided in the config"
        )
    })? {
        AuthorizationModeProperties::Jwt(jwt_opts) => {
            let algorithm = jwt_opts.algorithm;
            let claims = jwt_opts.claims.clone();
            let key = load_jwt_key(&jwt_opts.public_key_path, algorithm).await?;
            AuthorizationMode::Jwt(Jwt {
                key,
                claims,
                algorithm,
            })
        }
        AuthorizationModeProperties::Whitelist(whitelist_csv_path) => {
            let whitelist = load_authorization_whitelist(whitelist_csv_path)?;
            AuthorizationMode::Whitelist(Arc::new(Mutex::new(whitelist)))
        }
    };

    Ok(Some(auth_mode))
}
