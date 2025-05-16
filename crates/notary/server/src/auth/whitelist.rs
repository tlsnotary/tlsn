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

use crate::util::parse_csv_file;

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
pub(crate) fn authorization_whitelist_vec_into_hashmap(
    authorization_whitelist: Vec<AuthorizationWhitelistRecord>,
) -> HashMap<String, AuthorizationWhitelistRecord> {
    let mut hashmap = HashMap::new();
    authorization_whitelist.iter().for_each(|record| {
        hashmap.insert(record.api_key.clone(), record.to_owned());
    });
    hashmap
}

/// Load authorization whitelist
pub(super) fn load_authorization_whitelist(
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
    use std::{fs::OpenOptions, time::Duration};

    use csv::WriterBuilder;

    use super::*;

    #[tokio::test]
    async fn test_watch_and_reload_authorization_whitelist() {
        // Clone fixture auth whitelist for testing
        let original_whitelist_csv_path = "../tests-integration/fixture/auth/whitelist.csv";
        let whitelist_csv_path =
            "../tests-integration/fixture/auth/whitelist_copied.csv".to_string();
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
