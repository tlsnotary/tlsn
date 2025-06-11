use axum::http::{header, request::Parts};
use axum_core::extract::{FromRef, FromRequestParts};
use jsonwebtoken::{decode, TokenData, Validation};
use notary_common::X_API_KEY_HEADER;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, trace};

use crate::{
    auth::{AuthorizationMode, AuthorizationWhitelistRecord},
    types::NotaryGlobals,
    NotaryServerError,
};

/// Auth middleware to prevent DOS
pub struct AuthorizationMiddleware;

impl<S> FromRequestParts<S> for AuthorizationMiddleware
where
    NotaryGlobals: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let notary_globals = NotaryGlobals::from_ref(state);
        let Some(mode) = notary_globals.authorization_mode else {
            trace!("Skipping authorization as it's not enabled.");
            return Ok(Self);
        };

        match mode {
            AuthorizationMode::Whitelist(whitelist) => {
                let Some(auth_header) = parts
                    .headers
                    .get(X_API_KEY_HEADER)
                    .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
                else {
                    return Err(unauthorized("Missing API key"));
                };
                let entries = whitelist.entries.lock().unwrap();
                if api_key_is_valid(auth_header, &entries) {
                    trace!("Request authorized.");
                    Ok(Self)
                } else {
                    Err(unauthorized("Invalid API key"))
                }
            }
            AuthorizationMode::Jwt(jwt_config) => {
                let Some(auth_header) = parts
                    .headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
                else {
                    return Err(unauthorized("Missing JWT token"));
                };
                let raw_token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
                    unauthorized("Invalid Authorization header: expected 'Bearer <token>'")
                })?;
                let validation = Validation::new(jwt_config.algorithm.into());
                let claims = match decode::<Value>(raw_token, &jwt_config.key, &validation) {
                    Ok(TokenData { claims, .. }) => claims,
                    Err(err) => {
                        error!("Decoding JWT failed with error: {err:?}");
                        return Err(unauthorized("Invalid JWT token"));
                    }
                };
                if let Err(err) = jwt_config.validate(&claims) {
                    error!("Validating JWT failed with error: {err:?}");
                    return Err(unauthorized("Invalid JWT token"));
                };
                trace!("Request authorized.");
                Ok(Self)
            }
        }
    }
}

fn unauthorized(err_msg: impl ToString) -> NotaryServerError {
    let err_msg = err_msg.to_string();
    error!(err_msg);
    NotaryServerError::UnauthorizedProverRequest(err_msg)
}

/// Helper function to check if an API key is in whitelist
fn api_key_is_valid(
    api_key: &str,
    whitelist: &HashMap<String, AuthorizationWhitelistRecord>,
) -> bool {
    whitelist.get(api_key).is_some()
}

#[cfg(test)]
mod test {
    use super::{api_key_is_valid, HashMap};
    use crate::auth::{
        whitelist::authorization_whitelist_vec_into_hashmap, AuthorizationWhitelistRecord,
    };
    use std::sync::Arc;

    fn get_whitelist_fixture() -> HashMap<String, AuthorizationWhitelistRecord> {
        authorization_whitelist_vec_into_hashmap(vec![
            AuthorizationWhitelistRecord {
                name: "test-name-0".to_string(),
                api_key: "test-api-key-0".to_string(),
                created_at: "2023-10-18T07:38:53Z".to_string(),
            },
            AuthorizationWhitelistRecord {
                name: "test-name-1".to_string(),
                api_key: "test-api-key-1".to_string(),
                created_at: "2023-10-11T07:38:53Z".to_string(),
            },
            AuthorizationWhitelistRecord {
                name: "test-name-2".to_string(),
                api_key: "test-api-key-2".to_string(),
                created_at: "2022-10-11T07:38:53Z".to_string(),
            },
        ])
    }

    #[test]
    fn test_api_key_is_present() {
        let whitelist = get_whitelist_fixture();
        assert!(api_key_is_valid("test-api-key-0", &Arc::new(whitelist)));
    }

    #[test]
    fn test_api_key_is_absent() {
        let whitelist = get_whitelist_fixture();
        assert!(!api_key_is_valid("test-api-keY-0", &Arc::new(whitelist)));
    }
}
