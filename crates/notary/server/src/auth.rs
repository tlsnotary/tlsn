use eyre::{eyre, Result};
use jsonwebtoken::DecodingKey;
use notify::{
    event::ModifyKind, Error, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
};
use tracing::{debug, error, info};

use crate::{
    read_pem_file, util::parse_csv_file, AuthorizationModeProperties, JwtClaim, JwtClaimValueType,
    NotaryServerProperties,
};

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
            let key = load_jwt_key(&jwt_opts.public_key_path).await?;
            let claims = jwt_opts.claims.clone();
            AuthorizationMode::Jwt(Jwt { key, claims })
        }
        AuthorizationModeProperties::Whitelist(whitelist_csv_path) => {
            let whitelist = load_authorization_whitelist(whitelist_csv_path)?;
            AuthorizationMode::Whitelist(Arc::new(Mutex::new(whitelist)))
        }
    };

    Ok(Some(auth_mode))
}

/// Load JWT public key
async fn load_jwt_key(public_key_pem_path: &str) -> Result<DecodingKey> {
    let mut reader = read_pem_file(public_key_pem_path).await?;
    let mut key: Vec<u8> = Vec::new();
    reader.read_to_end(&mut key)?;
    let key = DecodingKey::from_rsa_pem(&key)?;
    Ok(key)
}

/// Load authorization whitelist
fn load_authorization_whitelist(
    whitelist_csv_path: &str,
) -> Result<HashMap<String, AuthorizationWhitelistRecord>> {
    // Load the csv
    let whitelist_csv = parse_csv_file::<AuthorizationWhitelistRecord>(whitelist_csv_path)
        .map_err(|err| eyre!("Failed to parse authorization whitelist csv: {:?}", err))?;
    // Convert the whitelist record into hashmap for faster lookup
    let whitelist_hashmap = authorization_whitelist_vec_into_hashmap(whitelist_csv);
    Ok(whitelist_hashmap)
}

// Setup a watcher to detect any changes to authorization whitelist
// When the list file is modified, the watcher thread will reload the whitelist
// The watcher is setup in a separate thread by the notify library which is
// synchronous
pub fn watch_and_reload_authorization_whitelist(
    authorization_whitelist: Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>,
    whitelist_csv_path: String,
) -> Result<RecommendedWatcher> {
    let whitelist_csv_path_cloned = whitelist_csv_path.clone();
    // Setup watcher by giving it a function that will be triggered when an event is
    // detected
    let mut watcher = RecommendedWatcher::new(
        move |event: Result<Event, Error>| {
            match event {
                Ok(event) => {
                    // Only reload whitelist if it's an event that modified the file data
                    if let EventKind::Modify(ModifyKind::Data(_)) = event.kind {
                        debug!("Authorization whitelist is modified");
                        match load_authorization_whitelist(&whitelist_csv_path_cloned) {
                            Ok(new_authorization_whitelist) => {
                                *authorization_whitelist.lock().unwrap() =
                                    new_authorization_whitelist;
                                info!("Successfully reloaded authorization whitelist!");
                            }
                            // Ensure that error from reloading doesn't bring the server down
                            Err(err) => error!("{err}"),
                        }
                    }
                }
                Err(err) => {
                    error!("Error occured when watcher detected an event: {err}")
                }
            }
        },
        notify::Config::default(),
    )
    .map_err(|err| eyre!("Error occured when setting up watcher for hot reload: {err}"))?;

    // Start watcher to listen to any changes on the whitelist file
    watcher
        .watch(Path::new(&whitelist_csv_path), RecursiveMode::Recursive)
        .map_err(|err| eyre!("Error occured when starting up watcher for hot reload: {err}"))?;

    // Need to return the watcher to parent function, else it will be dropped and
    // stop listening
    Ok(watcher)
}

#[cfg(test)]
mod test {
    use super::*;

    mod whitelist {
        use std::{fs::OpenOptions, time::Duration};

        use csv::WriterBuilder;

        use super::*;

        #[tokio::test]
        async fn test_watch_and_reload_authorization_whitelist() {
            // Clone fixture auth whitelist for testing
            let original_whitelist_csv_path = "./fixture/auth/whitelist.csv";
            let whitelist_csv_path = "./fixture/auth/whitelist_copied.csv".to_string();
            std::fs::copy(original_whitelist_csv_path, &whitelist_csv_path).unwrap();

            // Setup watcher
            let authorization_whitelist = load_authorization_whitelist(&whitelist_csv_path).expect(
                "Authorization whitelist csv from fixture should be able
    to be loaded",
            );
            let authorization_whitelist = Arc::new(Mutex::new(authorization_whitelist));
            let _watcher = watch_and_reload_authorization_whitelist(
                authorization_whitelist.clone(),
                whitelist_csv_path.clone(),
            )
            .expect("Watcher should be able to be setup successfully");

            // Sleep to buy a bit of time for hot reload task and watcher thread to run
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Write a new record to the whitelist to trigger modify event
            let new_record = AuthorizationWhitelistRecord {
                name: "unit-test-name".to_string(),
                api_key: "unit-test-api-key".to_string(),
                created_at: "unit-test-created-at".to_string(),
            };
            let file = OpenOptions::new()
                .append(true)
                .open(&whitelist_csv_path)
                .unwrap();
            let mut wtr = WriterBuilder::new()
                .has_headers(false) // Set to false to avoid writing header again
                .from_writer(file);
            wtr.serialize(new_record).unwrap();
            wtr.flush().unwrap();

            // Sleep to buy a bit of time for updated whitelist to be hot reloaded
            tokio::time::sleep(Duration::from_millis(50)).await;

            assert!(authorization_whitelist
                .lock()
                .unwrap()
                .contains_key("unit-test-api-key"));

            // Delete the cloned whitelist
            std::fs::remove_file(&whitelist_csv_path).unwrap();
        }
    }

    mod jwt {
        use serde_json::json;

        use super::*;

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
}
