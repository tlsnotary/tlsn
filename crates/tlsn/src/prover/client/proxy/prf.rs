use rustls::{
    CipherSuite, SupportedCipherSuite,
    crypto::{ActiveKeyExchange, CryptoProvider, tls12::Prf},
};
use std::sync::{Arc, OnceLock};

#[derive(Default, Clone)]
pub(crate) struct VerifyData {
    client_finished: Arc<OnceLock<Vec<u8>>>,
    server_finished: Arc<OnceLock<Vec<u8>>>,
    client_handshake_hash: Arc<OnceLock<Vec<u8>>>,
    server_handshake_hash: Arc<OnceLock<Vec<u8>>>,
    session_hash: Arc<OnceLock<Vec<u8>>>,
}

impl VerifyData {
    pub(crate) fn set_client_finished(&self, data: Vec<u8>, handshake_hash: Vec<u8>) {
        self.client_finished
            .set(data)
            .expect("client_finished should be set only once");
        self.client_handshake_hash
            .set(handshake_hash)
            .expect("client_handshake_hash should be set only once");
    }

    pub(crate) fn set_server_finished(&self, data: Vec<u8>, handshake_hash: Vec<u8>) {
        self.server_finished
            .set(data)
            .expect("server_finished should be set only once");
        self.server_handshake_hash
            .set(handshake_hash)
            .expect("server_handshake_hash should be set only once");
    }

    pub(crate) fn client_finished(&self) -> Option<Vec<u8>> {
        self.client_finished.get().cloned()
    }

    pub(crate) fn server_finished(&self) -> Option<Vec<u8>> {
        self.server_finished.get().cloned()
    }

    pub(crate) fn client_handshake_hash(&self) -> Option<Vec<u8>> {
        self.client_handshake_hash.get().cloned()
    }

    pub(crate) fn server_handshake_hash(&self) -> Option<Vec<u8>> {
        self.server_handshake_hash.get().cloned()
    }

    pub(crate) fn session_hash(&self) -> Option<Vec<u8>> {
        self.session_hash.get().cloned()
    }
}

opaque_debug::implement!(VerifyData);

struct InterceptingPrf {
    inner: &'static dyn Prf,
    verify_data: VerifyData,
}

impl Prf for InterceptingPrf {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let _ = self.verify_data.session_hash.set(seed.to_vec());
        self.inner
            .for_key_exchange(output, kx, peer_pub_key, label, seed)
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        self.inner.for_secret(output, secret, label, seed);

        if label == b"client finished" {
            self.verify_data
                .set_client_finished(output.to_vec(), seed.to_vec());
        } else if label == b"server finished" {
            self.verify_data
                .set_server_finished(output.to_vec(), seed.to_vec());
        }
    }

    fn fips(&self) -> bool {
        false
    }
}

pub(crate) fn create_intercepting_suites(
    provider: &CryptoProvider,
    verify_data: VerifyData,
    allowed_suites: &[CipherSuite],
) -> Vec<SupportedCipherSuite> {
    provider
        .cipher_suites
        .iter()
        .filter_map(|suite| match suite {
            SupportedCipherSuite::Tls12(tls12) if allowed_suites.contains(&tls12.common.suite) => {
                let intercepting_prf = &*Box::leak(Box::new(InterceptingPrf {
                    inner: tls12.prf_provider,
                    verify_data: verify_data.clone(),
                })) as &'static dyn Prf;

                let new_suite = Box::leak(Box::new(rustls::Tls12CipherSuite {
                    common: rustls::CipherSuiteCommon {
                        suite: tls12.common.suite,
                        hash_provider: tls12.common.hash_provider,
                        confidentiality_limit: tls12.common.confidentiality_limit,
                    },
                    prf_provider: intercepting_prf,
                    kx: tls12.kx,
                    sign: tls12.sign,
                    aead_alg: tls12.aead_alg,
                }));

                Some(SupportedCipherSuite::Tls12(new_suite))
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConnection;
    use std::sync::Arc;
    use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
    use tokio_util::{compat::TokioAsyncReadCompatExt, io::SyncIoBridge};

    const CIPHER_SUITE: &[CipherSuite] = &[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256];

    fn make_client_config(verify_data: VerifyData) -> Arc<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        let ca = rustls_pki_types::CertificateDer::from(CA_CERT_DER);
        root_store.add(ca).unwrap();

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = provider
            .kx_groups
            .iter()
            .filter(|g| g.name() == rustls::NamedGroup::secp256r1)
            .cloned()
            .collect();
        let cipher_suites = create_intercepting_suites(&provider, verify_data, CIPHER_SUITE);
        let provider = CryptoProvider {
            kx_groups,
            cipher_suites,
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
    async fn test_intercepting_prf() {
        let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
        tokio::spawn(tls_server_fixture::bind_test_server(server_socket.compat()));

        let verify_data = VerifyData::default();
        let config = make_client_config(verify_data.clone());
        let server_name = rustls_pki_types::ServerName::try_from(SERVER_DOMAIN).unwrap();

        tokio::task::spawn_blocking(move || {
            let mut stream = SyncIoBridge::new(client_socket);
            let mut conn = ClientConnection::new(config, server_name.to_owned()).unwrap();
            conn.complete_io(&mut stream).unwrap();
        })
        .await
        .unwrap();

        // TLS 1.2 verify data is 12 bytes.
        assert_eq!(verify_data.client_finished().unwrap().len(), 12);
        assert_eq!(verify_data.client_handshake_hash().unwrap().len(), 32);

        assert_eq!(verify_data.server_finished().unwrap().len(), 12);
        assert_eq!(verify_data.server_handshake_hash().unwrap().len(), 32);
    }
}
