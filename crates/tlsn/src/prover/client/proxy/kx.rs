use rustls::{
    NamedGroup, ProtocolVersion,
    crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup},
};
use std::sync::{Arc, OnceLock};

#[derive(Default, Clone)]
pub(crate) struct Pms {
    pms: Arc<OnceLock<Vec<u8>>>,
}

impl Pms {
    pub(crate) fn set(&mut self, pms: Vec<u8>) {
        self.pms.set(pms).expect("pms should be set only once");
    }

    pub(crate) fn get(&self) -> Option<Vec<u8>> {
        self.pms.get().cloned()
    }
}

opaque_debug::implement!(Pms);

#[derive(Debug)]
pub(crate) struct InterceptingKxGroup {
    inner: &'static dyn SupportedKxGroup,
    pms: Pms,
}

impl InterceptingKxGroup {
    pub(crate) fn from_allowed_groups(
        provider: &CryptoProvider,
        pms: Pms,
        groups: &[NamedGroup],
    ) -> Vec<&'static dyn SupportedKxGroup> {
        provider
            .kx_groups
            .iter()
            .filter(|g| groups.contains(&g.name()))
            .map(|&inner| {
                &*Box::leak(Box::new(InterceptingKxGroup {
                    inner,
                    pms: pms.clone(),
                })) as &'static dyn SupportedKxGroup
            })
            .collect()
    }
}

impl SupportedKxGroup for InterceptingKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(InterceptingKeyExchange {
            kx_group: self.inner.start()?,
            pms: self.pms.clone(),
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
    pms: Pms,
}

impl ActiveKeyExchange for InterceptingKeyExchange {
    fn complete(mut self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let secret = self.kx_group.complete(peer_pub_key)?;
        let pms = secret.secret_bytes();

        self.pms.set(pms.to_vec());
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
    use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
    use tokio_util::{compat::TokioAsyncReadCompatExt, io::SyncIoBridge};

    fn make_client_config(pms: Pms) -> Arc<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        let ca = rustls_pki_types::CertificateDer::from(CA_CERT_DER);
        root_store.add(ca).unwrap();

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let kx_groups =
            InterceptingKxGroup::from_allowed_groups(&provider, pms, &[NamedGroup::secp256r1]);
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
        tokio::spawn(tls_server_fixture::bind_test_server(server_socket.compat()));

        let pms = Pms::default();
        let config = make_client_config(pms.clone());
        let server_name = rustls_pki_types::ServerName::try_from(SERVER_DOMAIN).unwrap();

        tokio::task::spawn_blocking(move || {
            let mut stream = SyncIoBridge::new(client_socket);
            let mut conn = ClientConnection::new(config, server_name.to_owned()).unwrap();
            conn.complete_io(&mut stream).unwrap();
        })
        .await
        .unwrap();

        // PMS for secp256r1 ECDHE is 32 bytes.
        assert_eq!(pms.get().unwrap().len(), 32);
    }
}
