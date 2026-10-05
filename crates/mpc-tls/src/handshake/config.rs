use crate::handshake::{anchors::RootCertStore, error::Error, sign, verify};
use std::sync::Arc;
pub use tls_core::dns::*;
use tls_core::{
    key,
    msgs::enums::{CipherSuite, ProtocolVersion, SignatureScheme},
    suites::{DEFAULT_CIPHER_SUITES, SupportedCipherSuite},
    versions,
};

/// A trait for the ability to choose a certificate chain and
/// private key for the purposes of client authentication.
pub trait ResolvesClientCert: Send + Sync {
    /// With the server-supplied acceptable issuers in `acceptable_issuers`,
    /// the server's supported signature schemes in `sigschemes`,
    /// return a certificate chain and signing key to authenticate.
    ///
    /// `acceptable_issuers` is undecoded and unverified by the rustls
    /// library, but it should be expected to contain a DER encodings
    /// of X501 NAMEs.
    ///
    /// Return None to continue the handshake without any client
    /// authentication.  The server may reject the handshake later
    /// if it requires authentication.
    fn resolve(
        &self,
        acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>>;

    /// Return true if any certificates at all are available.
    fn has_certs(&self) -> bool;
}

/// Common configuration for (typically) all connections made by
/// a program.
///
/// Making one of these can be expensive, and should be
/// once per process rather than once per connection.
///
/// The supported cipher suites, key exchange groups and protocol versions
/// are fixed to what the MPC backend supports: they are not configurable.
///
/// # Defaults
///
/// * [`ClientConfig::max_fragment_size`]: the default is `None`: TLS packets
///   are not fragmented to a specific size.
/// * [`ClientConfig::alpn_protocols`]: the default is empty -- no ALPN protocol
///   is negotiated.
#[derive(Clone)]
pub struct ClientConfig {
    /// List of ciphersuites, in preference order.
    pub(super) cipher_suites: Vec<SupportedCipherSuite>,

    /// Which ALPN protocols we include in our client hello.
    /// If empty, no ALPN extension is sent.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// The maximum size of TLS message we'll emit.  If None, we don't limit TLS
    /// message lengths except to the 2**16 limit specified in the standard.
    ///
    /// rustls enforces an arbitrary minimum of 32 bytes for this field.
    /// Out of range values are reported as errors from ClientConnection::new.
    ///
    /// Setting this value to the TCP MSS may improve latency for stream-y
    /// workloads.
    pub max_fragment_size: Option<usize>,

    /// How to decide what client auth certificate/keys to use.
    pub(super) client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,

    /// Supported versions, in no particular order.  The default
    /// is all supported versions.
    pub(super) versions: versions::EnabledVersions,

    /// Whether to send the Server Name Indication (SNI) extension
    /// during the client handshake.
    ///
    /// The default is true.
    pub enable_sni: bool,

    /// How to verify the server certificate chain.
    pub(super) verifier: Arc<dyn verify::ServerCertVerifier>,
}

impl ClientConfig {
    /// Creates a new config which verifies the server certificate chain
    /// against the given root certificate store, without client
    /// authentication.
    pub fn new(root_store: RootCertStore) -> Self {
        Self::new_inner(root_store, Arc::new(FailResolveClientCert {}))
    }

    /// Creates a new config like [`ClientConfig::new`], additionally
    /// authenticating with the given certificate chain and matching private
    /// key if the server requests client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA, ECDSA, or Ed25519 private key.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn new_with_client_auth(
        root_store: RootCertStore,
        cert_chain: Vec<key::Certificate>,
        key_der: key::PrivateKey,
    ) -> Result<Self, Error> {
        let resolver = AlwaysResolvesClientCert::new(cert_chain, &key_der)?;
        Ok(Self::new_inner(root_store, Arc::new(resolver)))
    }

    /// Creates a new config like [`ClientConfig::new`], with a custom client
    /// certificate resolver.
    pub fn new_with_cert_resolver(
        root_store: RootCertStore,
        resolver: Arc<dyn ResolvesClientCert>,
    ) -> Self {
        Self::new_inner(root_store, resolver)
    }

    fn new_inner(root_store: RootCertStore, resolver: Arc<dyn ResolvesClientCert>) -> Self {
        Self {
            cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
            alpn_protocols: Vec::new(),
            max_fragment_size: None,
            client_auth_cert_resolver: resolver,
            versions: versions::EnabledVersions::new(versions::DEFAULT_VERSIONS),
            enable_sni: true,
            verifier: Arc::new(verify::WebPkiVerifier::new(root_store, None)),
        }
    }

    /// We support a given TLS version if it's quoted in the configured
    /// versions *and* at least one ciphersuite for this version is
    /// also configured.
    pub(crate) fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.versions.contains(v)
            && self
                .cipher_suites
                .iter()
                .any(|cs| cs.version().version == v)
    }

    pub(super) fn find_cipher_suite(&self, suite: CipherSuite) -> Option<SupportedCipherSuite> {
        self.cipher_suites
            .iter()
            .copied()
            .find(|&scs| scs.suite() == suite)
    }
}

// --- Client certificate resolvers (formerly handy.rs) ---

struct FailResolveClientCert {}

impl ResolvesClientCert for FailResolveClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

struct AlwaysResolvesClientCert(Arc<sign::CertifiedKey>);

impl AlwaysResolvesClientCert {
    fn new(chain: Vec<key::Certificate>, priv_key: &key::PrivateKey) -> Result<Self, Error> {
        let key = sign::any_supported_type(priv_key)
            .map_err(|_| Error::General("invalid private key".into()))?;
        Ok(Self(Arc::new(sign::CertifiedKey::new(chain, key))))
    }
}

impl ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}
