use eyre::Result;
use jsonwebtoken::{Algorithm as JwtAlgorithm, DecodingKey};
use serde_json::Value;
use strum::EnumString;
use tracing::error;

use crate::JwtClaim;

/// Custom error for JWT handling
#[derive(Debug, thiserror::Error, PartialEq)]
#[error("JWT validation error: {0}")]
pub struct JwtValidationError(String);

type JwtResult<T> = std::result::Result<T, JwtValidationError>;

/// JWT config which also encapsulates claims validation logic.
#[derive(Clone)]
pub struct Jwt {
    pub algorithm: Algorithm,
    pub key: DecodingKey,
    pub claims: Vec<JwtClaim>,
}

impl Jwt {
    pub fn validate(&self, claims: &Value) -> JwtResult<()> {
        Jwt::validate_claims(&self.claims, claims)
    }

    fn validate_claims(expected: &[JwtClaim], claims: &Value) -> JwtResult<()> {
        expected
            .iter()
            .try_for_each(|expected| Self::validate_claim(expected, claims))
    }

    fn validate_claim(expected: &JwtClaim, given: &Value) -> JwtResult<()> {
        let pointer = format!("/{}", expected.name.replace(".", "/"));
        let field = given.pointer(&pointer).ok_or(JwtValidationError(format!(
            "missing claim '{}'",
            expected.name
        )))?;

        let field_typed = field.as_str().ok_or(JwtValidationError(format!(
            "unexpected type for claim '{}': only strings are supported for claim values",
            expected.name,
        )))?;
        if !expected.values.is_empty() {
            expected.values.iter().any(|exp| exp == field_typed).then_some(()).ok_or_else(|| {
                        let expected_values = expected.values.iter().map(|x| format!("'{x}'")).collect::<Vec<String>>().join(", ");
                        JwtValidationError(format!(
                            "unexpected value for claim '{}': expected one of [ {expected_values} ], received '{field_typed}'", expected.name
                        ))
                    })?;
        }

        Ok(())
    }
}

#[derive(EnumString, Debug, Clone, Copy, PartialEq, Eq)]
#[strum(ascii_case_insensitive)]
/// Supported JWT signing algorithms
pub enum Algorithm {
    /// RSASSA-PSS using SHA-512
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS512,
    /// RSASSA-PSS using SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512
    PS512,
    /// ECDSA using SHA-256
    ES256,
    /// ECDSA using SHA-384
    ES384,
    /// Edwards-curve Digital Signature Algorithm (EdDSA)
    EdDSA,
}

impl From<Algorithm> for JwtAlgorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::RS256 => Self::RS256,
            Algorithm::RS384 => Self::RS384,
            Algorithm::RS512 => Self::RS512,
            Algorithm::PS256 => Self::PS256,
            Algorithm::PS384 => Self::PS384,
            Algorithm::PS512 => Self::PS512,
            Algorithm::ES256 => Self::ES256,
            Algorithm::ES384 => Self::ES384,
            Algorithm::EdDSA => Self::EdDSA,
        }
    }
}

/// Load JWT public key
pub(super) async fn load_jwt_key(
    public_key_pem_path: &str,
    algorithm: Algorithm,
) -> Result<DecodingKey> {
    let key_pem_bytes = tokio::fs::read(public_key_pem_path).await?;
    let key = match algorithm {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(&key_pem_bytes)?,
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(&key_pem_bytes)?,
        Algorithm::EdDSA => DecodingKey::from_ed_pem(&key_pem_bytes)?,
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
        Jwt::validate_claim(&expected, &given).unwrap();
    }

    #[test]
    fn validates_expected_value() {
        let expected = JwtClaim {
            name: "custom.host".to_string(),
            values: vec!["tlsn.com".to_string(), "api.tlsn.com".to_string()],
        };
        let given = json!({
            "exp": 12345,
            "custom": {
                "host": "api.tlsn.com",
            },
        });
        Jwt::validate_claim(&expected, &given).unwrap();
    }

    #[test]
    fn validates_with_unknown_claims() {
        let given = json!({
            "exp": 12345,
            "sub": "test",
            "what": "is_this",
        });
        Jwt::validate_claims(&[], &given).unwrap();
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
            Jwt::validate_claim(&expected, &given),
            Err(JwtValidationError("missing claim 'sub'".to_string()))
        )
    }

    #[test]
    fn fails_if_claim_has_unknown_value() {
        let expected = JwtClaim {
            name: "sub".to_string(),
            values: vec!["tlsn_prod".to_string(), "tlsn_test".to_string()],
        };
        let given = json!({
            "sub": "tlsn",
        });
        assert_eq!(
                Jwt::validate_claim(&expected, &given),
                Err(JwtValidationError("unexpected value for claim 'sub': expected one of [ 'tlsn_prod', 'tlsn_test' ], received 'tlsn'".to_string()))
            )
    }
}
