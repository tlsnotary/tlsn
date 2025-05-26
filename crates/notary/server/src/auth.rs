pub(crate) mod jwt;
pub(crate) mod whitelist;

use eyre::{eyre, Result};
use jwt::load_jwt_key;
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};
use strum::VariantNames;
use tracing::debug;
use whitelist::load_authorization_whitelist;

pub use jwt::{Algorithm, Jwt, JwtValidationError};
pub use whitelist::{
    watch_and_reload_authorization_whitelist, AuthorizationWhitelistRecord, Whitelist,
};

use crate::{AuthorizationModeProperties, NotaryServerProperties};

/// Supported authorization modes.
#[derive(Clone)]
pub enum AuthorizationMode {
    Jwt(Jwt),
    Whitelist(Whitelist),
}

impl AuthorizationMode {
    pub fn as_whitelist(&self) -> Option<&Whitelist> {
        match self {
            Self::Jwt(..) => None,
            Self::Whitelist(whitelist) => Some(whitelist),
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
            "Authorization enabled but failed to load either whitelist or jwt properties. They are either absent or malformed."
        )
    })? {
        AuthorizationModeProperties::Jwt(jwt_opts) => {
            let algorithm = Algorithm::from_str(&jwt_opts.algorithm).map_err(|_| {
                eyre!(
                    "Unexpected JWT signing algorithm specified: '{}'. Possible values are: {:?}",
                    jwt_opts.algorithm, Algorithm::VARIANTS,
                )
            })?;
            let claims = jwt_opts.claims.clone();
            let key = load_jwt_key(&jwt_opts.public_key_path, algorithm).await?;
            AuthorizationMode::Jwt(Jwt {
                key,
                claims,
                algorithm,
            })
        }
        AuthorizationModeProperties::Whitelist(whitelist_csv_path) => {
            let entries = load_authorization_whitelist(whitelist_csv_path)?;
            AuthorizationMode::Whitelist(Whitelist {
                entries: Arc::new(Mutex::new(entries)),
                csv_path: whitelist_csv_path.clone(),
            })
        }
    };

    Ok(Some(auth_mode))
}
