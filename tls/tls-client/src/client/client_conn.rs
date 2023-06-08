use async_trait::async_trait;

use super::hs;
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::{
    builder::{ConfigBuilder, WantsCipherSuites},
    conn::{CommonState, ConnectionCommon, Protocol, Side, State},
    error::Error,
    kx::SupportedKxGroup,
    sign, verify, Backend, KeyLog,
};
use std::{
    convert::TryFrom,
    error::Error as StdError,
    fmt, io, mem,
    ops::{Deref, DerefMut},
    sync::Arc,
};
pub use tls_core::dns::*;
use tls_core::{
    msgs::{
        enums::{CipherSuite, ProtocolVersion, SignatureScheme},
        handshake::ClientExtension,
        message::Message,
    },
    suites::SupportedCipherSuite,
    versions,
};

/// A trait for the ability to store client session data.
/// The keys and values are opaque.
///
/// Both the keys and values should be treated as
/// **highly sensitive data**, containing enough key material
/// to break all security of the corresponding session.
///
/// `put` is a mutating operation; this isn't expressed
/// in the type system to allow implementations freedom in
/// how to achieve interior mutability.  `Mutex` is a common
/// choice.
pub trait StoresClientSessions: Send + Sync {
    /// Stores a new `value` for `key`.  Returns `true`
    /// if the value was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Returns the latest value for `key`.  Returns `None`
    /// if there's no such value.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

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
/// These must be created via the [`ClientConfig::builder()`] function.
///
/// # Defaults
///
/// * [`ClientConfig::max_fragment_size`]: the default is `None`: TLS packets are not fragmented to a specific size.
/// * [`ClientConfig::session_storage`]: the default stores 256 sessions in memory.
/// * [`ClientConfig::alpn_protocols`]: the default is empty -- no ALPN protocol is negotiated.
/// * [`ClientConfig::key_log`]: key material is not logged.
#[derive(Clone)]
pub struct ClientConfig {
    /// List of ciphersuites, in preference order.
    pub(super) cipher_suites: Vec<SupportedCipherSuite>,

    /// List of supported key exchange algorithms, in preference order -- the
    /// first element is the highest priority.
    ///
    /// The first element in this list is the _default key share algorithm_,
    /// and in TLS1.3 a key share for it is sent in the client hello.
    pub(super) kx_groups: Vec<&'static SupportedKxGroup>,

    /// Which ALPN protocols we include in our client hello.
    /// If empty, no ALPN extension is sent.
    pub alpn_protocols: Vec<Vec<u8>>,

    /// How we store session data or tickets.
    pub session_storage: Arc<dyn StoresClientSessions>,

    /// The maximum size of TLS message we'll emit.  If None, we don't limit TLS
    /// message lengths except to the 2**16 limit specified in the standard.
    ///
    /// rustls enforces an arbitrary minimum of 32 bytes for this field.
    /// Out of range values are reported as errors from ClientConnection::new.
    ///
    /// Setting this value to the TCP MSS may improve latency for stream-y workloads.
    pub max_fragment_size: Option<usize>,

    /// How to decide what client auth certificate/keys to use.
    pub client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,

    /// Whether to support RFC5077 tickets.  You must provide a working
    /// `session_storage` member for this to have any meaningful
    /// effect.
    ///
    /// The default is true.
    pub enable_tickets: bool,

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

    /// How to output key material for debugging.  The default
    /// does nothing.
    pub key_log: Arc<dyn KeyLog>,

    /// Whether to send data on the first flight ("early data") in
    /// TLS 1.3 handshakes.
    ///
    /// The default is false.
    pub enable_early_data: bool,
}

impl ClientConfig {
    /// Create a builder to build up the client configuration.
    ///
    /// For more information, see the [`ConfigBuilder`] documentation.
    pub fn builder() -> ConfigBuilder<WantsCipherSuites> {
        ConfigBuilder {
            state: WantsCipherSuites(()),
        }
    }

    #[doc(hidden)]
    /// We support a given TLS version if it's quoted in the configured
    /// versions *and* at least one ciphersuite for this version is
    /// also configured.
    pub fn supports_version(&self, v: ProtocolVersion) -> bool {
        self.versions.contains(v)
            && self
                .cipher_suites
                .iter()
                .any(|cs| cs.version().version == v)
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    #[cfg(feature = "dangerous_configuration")]
    pub fn dangerous(&mut self) -> danger::DangerousClientConfig {
        danger::DangerousClientConfig { cfg: self }
    }

    pub(super) fn find_cipher_suite(&self, suite: CipherSuite) -> Option<SupportedCipherSuite> {
        self.cipher_suites
            .iter()
            .copied()
            .find(|&scs| scs.suite() == suite)
    }
}

/// Container for unsafe APIs
#[cfg(feature = "dangerous_configuration")]
pub(super) mod danger {
    use std::sync::Arc;

    use super::{verify::ServerCertVerifier, ClientConfig};

    /// Accessor for dangerous configuration options.
    pub struct DangerousClientConfig<'a> {
        /// The underlying ClientConfig
        pub cfg: &'a mut ClientConfig,
    }

    impl<'a> DangerousClientConfig<'a> {
        /// Overrides the default `ServerCertVerifier` with something else.
        pub fn set_certificate_verifier(&mut self, verifier: Arc<dyn ServerCertVerifier>) {
            self.cfg.verifier = verifier;
        }
    }
}

#[derive(Debug, PartialEq)]
enum EarlyDataState {
    Disabled,
    Ready,
    Accepted,
    AcceptedFinished,
    Rejected,
}

pub(super) struct EarlyData {
    state: EarlyDataState,
    left: usize,
}

impl EarlyData {
    fn new() -> Self {
        Self {
            left: 0,
            state: EarlyDataState::Disabled,
        }
    }

    pub(super) fn is_enabled(&self) -> bool {
        matches!(self.state, EarlyDataState::Ready | EarlyDataState::Accepted)
    }

    fn is_accepted(&self) -> bool {
        matches!(
            self.state,
            EarlyDataState::Accepted | EarlyDataState::AcceptedFinished
        )
    }

    pub(super) fn enable(&mut self, max_data: usize) {
        assert_eq!(self.state, EarlyDataState::Disabled);
        self.state = EarlyDataState::Ready;
        self.left = max_data;
    }

    pub(super) fn rejected(&mut self) {
        trace!("EarlyData rejected");
        self.state = EarlyDataState::Rejected;
    }

    pub(super) fn accepted(&mut self) {
        trace!("EarlyData accepted");
        assert_eq!(self.state, EarlyDataState::Ready);
        self.state = EarlyDataState::Accepted;
    }

    pub(super) fn finished(&mut self) {
        trace!("EarlyData finished");
        self.state = match self.state {
            EarlyDataState::Accepted => EarlyDataState::AcceptedFinished,
            _ => panic!("bad EarlyData state"),
        }
    }

    fn check_write(&mut self, sz: usize) -> io::Result<usize> {
        match self.state {
            EarlyDataState::Disabled => unreachable!(),
            EarlyDataState::Ready | EarlyDataState::Accepted => {
                let take = if self.left < sz {
                    mem::replace(&mut self.left, 0)
                } else {
                    self.left -= sz;
                    sz
                };

                Ok(take)
            }
            EarlyDataState::Rejected | EarlyDataState::AcceptedFinished => {
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            }
        }
    }

    fn bytes_left(&self) -> usize {
        self.left
    }
}

pub struct Initialized {
    server_name: ServerName,
    extra_exts: Vec<ClientExtension>,
    proto: Protocol,
    config: Arc<ClientConfig>,
}

#[async_trait]
impl State<ClientConnectionData> for Initialized {
    async fn start(
        self: Box<Self>,
        cx: &mut crate::conn::Context<'_>,
    ) -> Result<Box<dyn State<ClientConnectionData>>, Error> {
        hs::start_handshake(self.server_name, self.extra_exts, self.config, cx).await
    }

    async fn handle(
        self: Box<Self>,
        _cx: &mut crate::conn::Context<'_>,
        _message: Message,
    ) -> Result<Box<dyn State<ClientConnectionData>>, Error> {
        unreachable!()
    }
}

/// This represents a single TLS client connection.
pub struct ClientConnection {
    inner: ConnectionCommon,
}

impl fmt::Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClientConnection").finish()
    }
}

impl ClientConnection {
    /// Make a new ClientConnection.  `config` controls how
    /// we behave in the TLS protocol, `name` is the
    /// name of the server we want to talk to.
    pub fn new(
        config: Arc<ClientConfig>,
        backend: Box<dyn Backend>,
        name: ServerName,
    ) -> Result<Self, Error> {
        Self::new_inner(config, backend, name, Vec::new(), Protocol::Tcp)
    }

    fn new_inner(
        config: Arc<ClientConfig>,
        backend: Box<dyn Backend>,
        name: ServerName,
        extra_exts: Vec<ClientExtension>,
        proto: Protocol,
    ) -> Result<Self, Error> {
        let mut common_state = CommonState::new(config.max_fragment_size, Side::Client, backend)?;
        common_state.protocol = proto;
        let data = ClientConnectionData::new();

        let state = Box::new(Initialized {
            server_name: name,
            extra_exts,
            proto,
            config,
        });
        let inner = ConnectionCommon::new(state, data, common_state);

        Ok(Self { inner })
    }

    /// Returns True if the server signalled it will process early data.
    ///
    /// If you sent early data and this returns false at the end of the
    /// handshake then the server will not process the data.  This
    /// is not an error, but you may wish to resend the data.
    pub fn is_early_data_accepted(&self) -> bool {
        false
    }
}

impl Deref for ClientConnection {
    type Target = ConnectionCommon;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// State associated with a client connection.
pub struct ClientConnectionData {
    pub(super) early_data: EarlyData,
    pub(super) resumption_ciphersuite: Option<SupportedCipherSuite>,
}

impl ClientConnectionData {
    fn new() -> Self {
        Self {
            early_data: EarlyData::new(),
            resumption_ciphersuite: None,
        }
    }
}

impl crate::conn::SideData for ClientConnectionData {}
