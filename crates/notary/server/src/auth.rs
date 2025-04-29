use eyre::{eyre, Result};
use notify::{
    event::ModifyKind, Error, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};
use tracing::{debug, error, info};

use crate::{util::parse_csv_file, NotaryServerProperties};

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

/// Load authorization whitelist if it is enabled
pub fn load_authorization_whitelist(
    config: &NotaryServerProperties,
) -> Result<Option<HashMap<String, AuthorizationWhitelistRecord>>> {
    let authorization_whitelist = if !config.auth.enabled {
        debug!("Skipping authorization as it is turned off.");
        None
    } else {
        // Check if whitelist_csv_path is Some and convert to &str
        let whitelist_csv_path = config.auth.whitelist_path.as_deref().ok_or_else(|| {
            eyre!("Authorization whitelist csv path is not provided in the config")
        })?;
        // Load the csv
        let whitelist_csv = parse_csv_file::<AuthorizationWhitelistRecord>(whitelist_csv_path)
            .map_err(|err| eyre!("Failed to parse authorization whitelist csv: {:?}", err))?;
        // Convert the whitelist record into hashmap for faster lookup
        let whitelist_hashmap = authorization_whitelist_vec_into_hashmap(whitelist_csv);
        Some(whitelist_hashmap)
    };
    Ok(authorization_whitelist)
}

// Setup a watcher to detect any changes to authorization whitelist
// When the list file is modified, the watcher thread will reload the whitelist
// The watcher is setup in a separate thread by the notify library which is
// synchronous
pub fn watch_and_reload_authorization_whitelist(
    config: NotaryServerProperties,
    authorization_whitelist: Option<Arc<Mutex<HashMap<String, AuthorizationWhitelistRecord>>>>,
) -> Result<Option<RecommendedWatcher>> {
    // Only setup the watcher if auth whitelist is loaded
    let watcher = if let Some(authorization_whitelist) = authorization_whitelist {
        let cloned_config = config.clone();
        // Setup watcher by giving it a function that will be triggered when an event is
        // detected
        let mut watcher = RecommendedWatcher::new(
            move |event: Result<Event, Error>| {
                match event {
                    Ok(event) => {
                        // Only reload whitelist if it's an event that modified the file data
                        if let EventKind::Modify(ModifyKind::Data(_)) = event.kind {
                            debug!("Authorization whitelist is modified");
                            match load_authorization_whitelist(&cloned_config) {
                                Ok(Some(new_authorization_whitelist)) => {
                                    *authorization_whitelist.lock().unwrap() = new_authorization_whitelist;
                                    info!("Successfully reloaded authorization whitelist!");
                                }
                                Ok(None) => unreachable!(
                                    "Authorization whitelist will never be None as the auth module is enabled"
                                ),
                                // Ensure that error from reloading doesn't bring the server down
                                Err(err) => error!("{err}"),
                            }
                        }
                    },
                    Err(err) => {
                        error!("Error occured when watcher detected an event: {err}")
                    }
                }
            },
            notify::Config::default(),
        )
        .map_err(|err| eyre!("Error occured when setting up watcher for hot reload: {err}"))?;

        // Check if whitelist_csv_path is Some and convert to &str
        let whitelist_csv_path = config.auth.whitelist_path.as_deref().ok_or_else(|| {
            eyre!("Authorization whitelist csv path is not provided in the config")
        })?;

        // Start watcher to listen to any changes on the whitelist file
        watcher
            .watch(Path::new(whitelist_csv_path), RecursiveMode::Recursive)
            .map_err(|err| eyre!("Error occured when starting up watcher for hot reload: {err}"))?;

        Some(watcher)
    } else {
        // Skip setup the watcher if auth whitelist is not loaded
        None
    };
    // Need to return the watcher to parent function, else it will be dropped and
    // stop listening
    Ok(watcher)
}

#[cfg(test)]
mod test {
    use std::{fs::OpenOptions, time::Duration};

    use csv::WriterBuilder;

    use crate::AuthorizationProperties;

    use super::*;

    #[tokio::test]
    async fn test_watch_and_reload_authorization_whitelist() {
        // Clone fixture auth whitelist for testing
        let original_whitelist_csv_path = "./fixture/auth/whitelist.csv";
        let whitelist_csv_path = "./fixture/auth/whitelist_copied.csv".to_string();
        std::fs::copy(original_whitelist_csv_path, &whitelist_csv_path).unwrap();

        // Setup watcher
        let config = NotaryServerProperties {
            auth: AuthorizationProperties {
                enabled: true,
                whitelist_path: Some(whitelist_csv_path.clone()),
            },
            ..Default::default()
        };
        let authorization_whitelist = load_authorization_whitelist(&config)
            .expect("Authorization whitelist csv from fixture should be able to be loaded")
            .as_ref()
            .map(|whitelist| Arc::new(Mutex::new(whitelist.clone())));
        let _watcher = watch_and_reload_authorization_whitelist(
            config.clone(),
            authorization_whitelist.as_ref().map(Arc::clone),
        )
        .expect("Watcher should be able to be setup successfully")
        .expect("Watcher should be set up and not None");

        // Sleep to buy a bit of time for hot reload task and watcher thread to run
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Write a new record to the whitelist to trigger modify event
        let new_record = AuthorizationWhitelistRecord {
            name: "unit-test-name".to_string(),
            api_key: "unit-test-api-key".to_string(),
            created_at: "unit-test-created-at".to_string(),
        };
        if let Some(ref path) = config.auth.whitelist_path {
            let file = OpenOptions::new().append(true).open(path).unwrap();
            let mut wtr = WriterBuilder::new()
                .has_headers(false) // Set to false to avoid writing header again
                .from_writer(file);
            wtr.serialize(new_record).unwrap();
            wtr.flush().unwrap();
        } else {
            panic!("Whitelist CSV path should be provided in the config");
        }
        // Sleep to buy a bit of time for updated whitelist to be hot reloaded
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(authorization_whitelist
            .unwrap()
            .lock()
            .unwrap()
            .contains_key("unit-test-api-key"));

        // Delete the cloned whitelist
        std::fs::remove_file(&whitelist_csv_path).unwrap();
    }
}
