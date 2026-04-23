//! KeyLog implementation that captures the TLS 1.2 master secret.

use rustls::KeyLog;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(crate) struct MasterSecretLog {
    ms: Mutex<Vec<u8>>,
}

impl MasterSecretLog {
    pub(crate) fn take(&self) -> Vec<u8> {
        std::mem::take(
            &mut *self
                .ms
                .lock()
                .expect("should be able to acquire lock for ms"),
        )
    }
}

impl KeyLog for MasterSecretLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        if label == "CLIENT_RANDOM" {
            *self
                .ms
                .lock()
                .expect("should be able to acquire lock for ms") = secret.to_vec();
        }
    }

    fn will_log(&self, label: &str) -> bool {
        label == "CLIENT_RANDOM"
    }
}
