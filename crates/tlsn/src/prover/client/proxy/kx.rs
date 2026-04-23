//! Tooling for interception of key exchange.
//!
//! # Process-global state
//!
//! `PMS` and `GROUPS` are process-wide singletons. This is a consequence of
//! rustls requiring `&'static dyn SupportedKxGroup` references in its
//! `CryptoProvider`, which prevents per-session allocation.
//!
//! **Only one proxy-mode TLS session may be active per process at a time.**
//! Running concurrent proxy sessions will cause one session to observe the
//! other's pre-master secret (or an empty vec), leading to protocol failure.
//! `GROUPS` is initialized once via `OnceLock` and reused for all subsequent
//! sessions — the first `CryptoProvider` configuration wins for the process
//! lifetime.

use rustls::{
    NamedGroup, ProtocolVersion,
    crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup},
};
use std::sync::{Mutex, OnceLock};

// Process-global storage for the pre-master secret extracted during the key
// exchange. Consumed via `take_pms()` after the handshake completes.
// See module-level docs for concurrency constraints.
static PMS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

pub(crate) fn take_pms() -> Vec<u8> {
    std::mem::take(&mut *PMS.lock().expect("should be able to acquire lock for pms"))
}

static GROUPS: OnceLock<Vec<InterceptingKxGroup>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct InterceptingKxGroup {
    inner: &'static dyn SupportedKxGroup,
}

impl InterceptingKxGroup {
    pub(crate) fn from_allowed_groups(
        provider: &CryptoProvider,
        groups: &[NamedGroup],
    ) -> Vec<&'static dyn SupportedKxGroup> {
        let wrappers = GROUPS.get_or_init(|| {
            provider
                .kx_groups
                .iter()
                .map(|&inner| InterceptingKxGroup { inner })
                .collect()
        });
        wrappers
            .iter()
            .filter(|w| groups.contains(&w.inner.name()))
            .map(|w| w as &'static dyn SupportedKxGroup)
            .collect()
    }
}

impl SupportedKxGroup for InterceptingKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(InterceptingKeyExchange {
            kx_group: self.inner.start()?,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.inner.name()
    }

    fn fips(&self) -> bool {
        false
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        self.inner.usable_for_version(version)
    }
}

struct InterceptingKeyExchange {
    kx_group: Box<dyn ActiveKeyExchange>,
}

impl ActiveKeyExchange for InterceptingKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let secret = self.kx_group.complete(peer_pub_key)?;
        let mut pms = PMS.lock().expect("should be able to acquire lock for pms");
        *pms = secret.secret_bytes().to_vec();
        Ok(secret)
    }

    fn pub_key(&self) -> &[u8] {
        self.kx_group.pub_key()
    }

    fn group(&self) -> NamedGroup {
        self.kx_group.group()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConnection;
    use std::sync::Arc;
    use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN, bind_test_server};
    use tokio_util::{compat::TokioAsyncReadCompatExt, io::SyncIoBridge};

    fn make_client_config() -> Arc<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        let ca = rustls_pki_types::CertificateDer::from(CA_CERT_DER);
        root_store.add(ca).unwrap();

        let provider = rustls::crypto::ring::default_provider();
        let kx_groups =
            InterceptingKxGroup::from_allowed_groups(&provider, &[NamedGroup::secp256r1]);
        let provider = CryptoProvider {
            kx_groups,
            ..provider
        };

        let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Arc::new(config)
    }

    #[tokio::test]
    async fn test_intercepting_kx() {
        let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
        tokio::spawn(bind_test_server(server_socket.compat()));

        let config = make_client_config();
        let server_name = rustls_pki_types::ServerName::try_from(SERVER_DOMAIN).unwrap();

        tokio::task::spawn_blocking(move || {
            let mut stream = SyncIoBridge::new(client_socket);
            let mut conn = ClientConnection::new(config, server_name.to_owned()).unwrap();
            conn.complete_io(&mut stream).unwrap();
        })
        .await
        .unwrap();

        // PMS for secp256r1 ECDHE is 32 bytes.
        assert_eq!(take_pms().len(), 32);
    }
}
