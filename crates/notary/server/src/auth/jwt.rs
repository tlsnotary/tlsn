use eyre::Result;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;
use std::io::Read;
use tracing::error;

use crate::{read_pem_file, JwtClaim, JwtClaimValueType};

/// Custom error for JWT handling
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum JwtError {
    #[error("unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(Algorithm),
    #[error("JWT validation error: {0}")]
    Validation(String),
}

type JwtResult<T> = std::result::Result<T, JwtError>;

/// JWT config which also encapsulates claims validation logic.
#[derive(Clone)]
pub struct Jwt {
    pub algorithm: Algorithm,
    pub key: DecodingKey,
    pub claims: Vec<JwtClaim>,
}

impl Jwt {
    pub fn validate(&self, claims: Value) -> JwtResult<()> {
        Jwt::validate_claims(&self.claims, claims)
    }

    fn validate_claims(expected: &[JwtClaim], claims: Value) -> JwtResult<()> {
        expected
            .iter()
            .try_for_each(|expected| Self::validate_claim(expected, claims.clone()))
    }

    fn validate_claim(expected: &JwtClaim, given: Value) -> JwtResult<()> {
        let field = Jwt::get_field(&expected.name, &given).ok_or(JwtError::Validation(format!(
            "missing claim '{}'",
            expected.name
        )))?;

        match expected.value_type {
            JwtClaimValueType::String => {
                let field_typed = field.as_str().ok_or(JwtError::Validation(format!(
                    "unexpected type for claim '{}': expected '{:?}'",
                    expected.name, expected.value_type
                )))?;
                if !expected.values.is_empty() {
                    expected.values.iter().any(|exp| exp == field_typed).then_some(()).ok_or_else(|| {
                        let expected_values = expected.values.iter().map(|x| format!("'{x}'")).collect::<Vec<String>>().join(", ");
                        JwtError::Validation(format!(
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

/// Load JWT public key
pub(super) async fn load_jwt_key(
    public_key_pem_path: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey> {
    let mut reader = read_pem_file(public_key_pem_path).await?;
    let mut key_pem_bytes: Vec<u8> = Vec::new();
    reader.read_to_end(&mut key_pem_bytes)?;
    let key = match algorithm {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(&key_pem_bytes)?,
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(&key_pem_bytes)?,
        Algorithm::EdDSA => DecodingKey::from_ed_pem(&key_pem_bytes)?,
        _ => return Err(JwtError::UnsupportedAlgorithm(algorithm).into()),
    };
    Ok(key)
}

#[cfg(test)]
mod test {
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
            Err(JwtError::Validation("missing claim 'sub'".to_string()))
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
                Err(JwtError::Validation("unexpected value for claim 'sub': expected one of [ 'tlsn_prod', 'tlsn_test' ], received 'tlsn'".to_string()))
            )
    }
}
