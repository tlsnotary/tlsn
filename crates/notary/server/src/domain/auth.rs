use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::config::{JwtClaim, JwtClaimValueType};

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

/// Custom error returned if JWT claims validation fails.
#[derive(Debug, thiserror::Error, PartialEq)]
#[error("JWT validation error: {0}")]
pub struct JwtValidationError(String);

/// JWT config which also encapsulates claims validation logic.
#[derive(Clone)]
pub struct Jwt {
    pub key: DecodingKey,
    pub claims: Vec<JwtClaim>,
}

impl Jwt {
    pub fn validate(&self, claims: Value) -> Result<(), JwtValidationError> {
        Jwt::validate_claims(&self.claims, claims)
    }

    fn validate_claims(expected: &[JwtClaim], claims: Value) -> Result<(), JwtValidationError> {
        expected
            .iter()
            .try_for_each(|expected| Self::validate_claim(expected, claims.clone()))
    }

    fn validate_claim(expected: &JwtClaim, given: Value) -> Result<(), JwtValidationError> {
        let field = Jwt::get_field(&expected.name, &given).ok_or(JwtValidationError(format!(
            "missing claim '{}'",
            expected.name
        )))?;

        match expected.value_type {
            JwtClaimValueType::String => {
                let field_typed = field.as_str().ok_or(JwtValidationError(format!(
                    "unexpected type for claim '{}': expected '{:?}'",
                    expected.name, expected.value_type
                )))?;
                if !expected.values.is_empty() {
                    expected.values.iter().any(|exp| exp == field_typed).then_some(()).ok_or_else(|| {
                        let expected_values = expected.values.iter().map(|x| format!("'{x}'")).collect::<Vec<String>>().join(", ");
                        JwtValidationError(format!(
                            "unexpected value for claim '{}': expected one of [ {expected_values} ], received '{field_typed}'", expected.name
                        ))
                    })?;
                }
            }
        }

        Ok(())
    }

    fn get_field<'a>(path: &'a str, value: &'a Value) -> Option<&'a Value> {
        let (field, path) = match path.split_once('.') {
            Some((field, path)) => (field, Some(path)),
            None => (path, None),
        };
        if let Some(value) = value.get(field) {
            match path {
                Some(path) => Jwt::get_field(path, value),
                None => Some(value),
            }
        } else {
            None
        }
    }
}

/// Custom HTTP header used for specifying a whitelisted API key
pub const X_API_KEY_HEADER: &str = "X-API-Key";

/// Structure of each whitelisted record of the API key whitelist for
/// authorization purpose
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthorizationWhitelistRecord {
    pub name: String,
    pub api_key: String,
    pub created_at: String,
}

/// Convert whitelist data structure from vector to hashmap using api_key as the
/// key to speed up lookup
pub fn authorization_whitelist_vec_into_hashmap(
    authorization_whitelist: Vec<AuthorizationWhitelistRecord>,
) -> HashMap<String, AuthorizationWhitelistRecord> {
    let mut hashmap = HashMap::new();
    authorization_whitelist.iter().for_each(|record| {
        hashmap.insert(record.api_key.clone(), record.to_owned());
    });
    hashmap
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_presence() {
        let expected = JwtClaim {
            name: "sub".to_string(),
            ..Default::default()
        };
        let given = json!({
            "exp": 12345,
            "sub": "test",
        });
        assert!(Jwt::validate_claim(&expected, given).is_ok());
    }

    #[test]
    fn validates_expected_value() {
        let expected = JwtClaim {
            name: "custom.host".to_string(),
            values: vec!["tlsn.com".to_string(), "api.tlsn.com".to_string()],
            ..Default::default()
        };
        let given = json!({
            "exp": 12345,
            "custom": {
                "host": "api.tlsn.com",
            },
        });
        assert!(Jwt::validate_claim(&expected, given).is_ok())
    }

    #[test]
    fn validates_with_unknown_claims() {
        let given = json!({
            "exp": 12345,
            "sub": "test",
            "what": "is_this",
        });
        assert!(Jwt::validate_claims(&[], given).is_ok())
    }

    #[test]
    fn fails_if_claim_missing() {
        let expected = JwtClaim {
            name: "sub".to_string(),
            ..Default::default()
        };
        let given = json!({
            "exp": 12345,
            "host": "localhost",
        });
        assert_eq!(
            Jwt::validate_claim(&expected, given),
            Err(JwtValidationError("missing claim 'sub'".to_string()))
        )
    }

    #[test]
    fn fails_if_claim_has_unknown_value() {
        let expected = JwtClaim {
            name: "sub".to_string(),
            values: vec!["tlsn_prod".to_string(), "tlsn_test".to_string()],
            ..Default::default()
        };
        let given = json!({
            "sub": "tlsn",
        });
        assert_eq!(
            Jwt::validate_claim(&expected, given),
            Err(JwtValidationError("unexpected value for claim 'sub': expected one of [ 'tlsn_prod', 'tlsn_test' ], received 'tlsn'".to_string()))
        )
    }
}
