use async_trait::async_trait;
use axum::http::{header, request::Parts};
use axum_core::extract::{FromRef, FromRequestParts};
use std::collections::HashMap;
use tracing::{error, trace};

use crate::{
    domain::{auth::AuthorizationWhitelistRecord, notary::NotaryGlobals},
    NotaryServerError,
};

/// Auth middleware to prevent DOS
pub struct AuthorizationMiddleware;

#[async_trait]
impl<S> FromRequestParts<S> for AuthorizationMiddleware
where
    NotaryGlobals: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let notary_globals = NotaryGlobals::from_ref(state);
        let Some(whitelist) = notary_globals.authorization_whitelist else {
            trace!("Skipping authorization as whitelist is not set.");
            return Ok(Self);
        };
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| std::str::from_utf8(value.as_bytes()).ok());

        match auth_header {
            Some(auth_header) => {
                let whitelist = whitelist.lock().unwrap();
                if api_key_is_valid(auth_header, &whitelist) {
                    trace!("Request authorized.");
                    Ok(Self)
                } else {
                    let err_msg = "Invalid API key.".to_string();
                    error!(err_msg);
                    Err(NotaryServerError::UnauthorizedProverRequest(err_msg))
                }
            }
            None => {
                let err_msg = "Missing API key.".to_string();
                error!(err_msg);
                Err(NotaryServerError::UnauthorizedProverRequest(err_msg))
            }
        }
    }
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
    use crate::domain::auth::{
        authorization_whitelist_vec_into_hashmap, AuthorizationWhitelistRecord,
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
