//! Configuration types.

use core::fmt;
use rangeset::ToRangeSet;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{error::Error, sync::LazyLock};

use crate::{
    connection::ServerName,
    transcript::{Direction, Idx, PartialTranscript, Transcript, TranscriptCommitConfig},
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
};

// Default is 32 bytes to decrypt the TLS protocol messages.
const DEFAULT_MAX_RECV_ONLINE: usize = 32;
// Default maximum number of TLS records to allow.
//
// This would allow for up to 50Mb upload from prover to verifier.
const DEFAULT_RECORDS_LIMIT: usize = 256;

// Current version that is running.
static VERSION: LazyLock<Version> = LazyLock::new(|| {
    Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|err| ProtocolConfigError::new(ErrorKind::Version, err))
        .unwrap()
});

/// Configuration for the prover.
#[derive(Debug, Clone, derive_builder::Builder, Serialize, Deserialize)]
pub struct ProverConfig {
    /// The server DNS name.
    #[builder(setter(into))]
    server_name: ServerName,
    /// Protocol configuration to be checked with the verifier.
    protocol_config: ProtocolConfig,
    /// TLS configuration.
    #[builder(default)]
    tls_config: TlsConfig,
}

impl ProverConfig {
    /// Creates a new builder for `ProverConfig`.
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }

    /// Returns the server DNS name.
    pub fn server_name(&self) -> &ServerName {
        &self.server_name
    }

    /// Returns the protocol configuration.
    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// Returns the TLS configuration.
    pub fn tls_config(&self) -> &TlsConfig {
        &self.tls_config
    }
}

/// Configuration for the [`Verifier`](crate::tls::Verifier).
#[allow(missing_docs)]
#[derive(derive_builder::Builder, Serialize, Deserialize)]
#[builder(pattern = "owned")]
pub struct VerifierConfig {
    protocol_config_validator: ProtocolConfigValidator,
    #[builder(setter(strip_option), default)]
    root_store: Option<RootCertStore>,
}

impl std::fmt::Debug for VerifierConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierConfig")
            .field("protocol_config_validator", &self.protocol_config_validator)
            .finish_non_exhaustive()
    }
}

impl VerifierConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns the protocol configuration validator.
    pub fn protocol_config_validator(&self) -> &ProtocolConfigValidator {
        &self.protocol_config_validator
    }

    /// Returns the root certificate store.
    pub fn root_store(&self) -> Option<&RootCertStore> {
        self.root_store.as_ref()
    }
}

/// Configuration for the prover's TLS connection.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Root certificates.
    root_store: Option<RootCertStore>,
    /// Certificate chain and a matching private key for client
    /// authentication.
    client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
}

impl TlsConfig {
    /// Creates a new builder for `TlsConfig`.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }

    /// Returns the root certificate store.
    pub fn root_store(&self) -> Option<&RootCertStore> {
        self.root_store.as_ref()
    }

    /// Returns a certificate chain and a matching private key for client
    /// authentication.
    pub fn client_auth(&self) -> &Option<(Vec<CertificateDer>, PrivateKeyDer)> {
        &self.client_auth
    }
}

/// Builder for [`TlsConfig`].
#[derive(Debug, Default)]
pub struct TlsConfigBuilder {
    root_store: Option<RootCertStore>,
    client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
}

impl TlsConfigBuilder {
    /// Sets the root certificates to use for verifying the server's
    /// certificate.
    pub fn root_store(&mut self, store: RootCertStore) -> &mut Self {
        self.root_store = Some(store);
        self
    }

    /// Sets a DER-encoded certificate chain and a matching private key for
    /// client authentication.
    ///
    /// Often the chain will consist of a single end-entity certificate.
    ///
    /// # Arguments
    ///
    /// * `cert_key` - A tuple containing the certificate chain and the private
    ///   key.
    ///
    ///   - Each certificate in the chain must be in the X.509 format.
    ///   - The key must be in the ASN.1 format (either PKCS#8 or PKCS#1).
    pub fn client_auth(&mut self, cert_key: (Vec<CertificateDer>, PrivateKeyDer)) -> &mut Self {
        self.client_auth = Some(cert_key);
        self
    }

    /// Builds the TLS configuration.
    pub fn build(self) -> Result<TlsConfig, TlsConfigError> {
        Ok(TlsConfig {
            root_store: self.root_store,
            client_auth: self.client_auth,
        })
    }
}

/// TLS configuration error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TlsConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("tls config error")]
enum ErrorRepr {}

/// Protocol configuration to be set up initially by prover and verifier.
#[derive(derive_builder::Builder, Clone, Debug, Deserialize, Serialize)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct ProtocolConfig {
    /// Maximum number of bytes that can be sent.
    max_sent_data: usize,
    /// Maximum number of application data records that can be sent.
    #[builder(setter(strip_option), default)]
    max_sent_records: Option<usize>,
    /// Maximum number of bytes that can be decrypted online, i.e. while the
    /// MPC-TLS connection is active.
    #[builder(default = "DEFAULT_MAX_RECV_ONLINE")]
    max_recv_data_online: usize,
    /// Maximum number of bytes that can be received.
    max_recv_data: usize,
    /// Maximum number of received application data records that can be
    /// decrypted online, i.e. while the MPC-TLS connection is active.
    #[builder(setter(strip_option), default)]
    max_recv_records_online: Option<usize>,
    /// Whether the `deferred decryption` feature is toggled on from the start
    /// of the MPC-TLS connection.
    #[builder(default = "true")]
    defer_decryption_from_start: bool,
    /// Network settings.
    #[builder(default)]
    network: NetworkSetting,
    /// Version that is being run by prover/verifier.
    #[builder(setter(skip), default = "VERSION.clone()")]
    version: Version,
}

impl ProtocolConfigBuilder {
    fn validate(&self) -> Result<(), String> {
        if self.max_recv_data_online > self.max_recv_data {
            return Err(
                "max_recv_data_online must be smaller or equal to max_recv_data".to_string(),
            );
        }
        Ok(())
    }
}

impl ProtocolConfig {
    /// Creates a new builder for `ProtocolConfig`.
    pub fn builder() -> ProtocolConfigBuilder {
        ProtocolConfigBuilder::default()
    }

    /// Returns the maximum number of bytes that can be sent.
    pub fn max_sent_data(&self) -> usize {
        self.max_sent_data
    }

    /// Returns the maximum number of application data records that can
    /// be sent.
    pub fn max_sent_records(&self) -> Option<usize> {
        self.max_sent_records
    }

    /// Returns the maximum number of bytes that can be decrypted online.
    pub fn max_recv_data_online(&self) -> usize {
        self.max_recv_data_online
    }

    /// Returns the maximum number of bytes that can be received.
    pub fn max_recv_data(&self) -> usize {
        self.max_recv_data
    }

    /// Returns the maximum number of received application data records that
    /// can be decrypted online.
    pub fn max_recv_records_online(&self) -> Option<usize> {
        self.max_recv_records_online
    }

    /// Returns whether the `deferred decryption` feature is toggled on from the
    /// start of the MPC-TLS connection.
    pub fn defer_decryption_from_start(&self) -> bool {
        self.defer_decryption_from_start
    }

    /// Returns the network settings.
    pub fn network(&self) -> NetworkSetting {
        self.network
    }
}

/// Protocol configuration validator used by checker (i.e. verifier) to perform
/// compatibility check with the peer's (i.e. the prover's) configuration.
#[derive(derive_builder::Builder, Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolConfigValidator {
    /// Maximum number of bytes that can be sent.
    max_sent_data: usize,
    /// Maximum number of application data records that can be sent.
    #[builder(default = "DEFAULT_RECORDS_LIMIT")]
    max_sent_records: usize,
    /// Maximum number of bytes that can be received.
    max_recv_data: usize,
    /// Maximum number of application data records that can be received online.
    #[builder(default = "DEFAULT_RECORDS_LIMIT")]
    max_recv_records_online: usize,
    /// Version that is being run by checker.
    #[builder(setter(skip), default = "VERSION.clone()")]
    version: Version,
}

impl ProtocolConfigValidator {
    /// Creates a new builder for `ProtocolConfigValidator`.
    pub fn builder() -> ProtocolConfigValidatorBuilder {
        ProtocolConfigValidatorBuilder::default()
    }

    /// Returns the maximum number of bytes that can be sent.
    pub fn max_sent_data(&self) -> usize {
        self.max_sent_data
    }

    /// Returns the maximum number of application data records that can
    /// be sent.
    pub fn max_sent_records(&self) -> usize {
        self.max_sent_records
    }

    /// Returns the maximum number of bytes that can be received.
    pub fn max_recv_data(&self) -> usize {
        self.max_recv_data
    }

    /// Returns the maximum number of application data records that can
    /// be received online.
    pub fn max_recv_records_online(&self) -> usize {
        self.max_recv_records_online
    }

    /// Performs compatibility check of the protocol configuration between
    /// prover and verifier.
    pub fn validate(&self, config: &ProtocolConfig) -> Result<(), ProtocolConfigError> {
        self.check_max_transcript_size(config.max_sent_data, config.max_recv_data)?;
        self.check_max_records(config.max_sent_records, config.max_recv_records_online)?;
        self.check_version(&config.version)?;
        Ok(())
    }

    // Checks if both the sent and recv data are within limits.
    fn check_max_transcript_size(
        &self,
        max_sent_data: usize,
        max_recv_data: usize,
    ) -> Result<(), ProtocolConfigError> {
        if max_sent_data > self.max_sent_data {
            return Err(ProtocolConfigError::max_transcript_size(format!(
                "max_sent_data {:?} is greater than the configured limit {:?}",
                max_sent_data, self.max_sent_data,
            )));
        }

        if max_recv_data > self.max_recv_data {
            return Err(ProtocolConfigError::max_transcript_size(format!(
                "max_recv_data {:?} is greater than the configured limit {:?}",
                max_recv_data, self.max_recv_data,
            )));
        }

        Ok(())
    }

    fn check_max_records(
        &self,
        max_sent_records: Option<usize>,
        max_recv_records_online: Option<usize>,
    ) -> Result<(), ProtocolConfigError> {
        if let Some(max_sent_records) = max_sent_records {
            if max_sent_records > self.max_sent_records {
                return Err(ProtocolConfigError::max_record_count(format!(
                    "max_sent_records {} is greater than the configured limit {}",
                    max_sent_records, self.max_sent_records,
                )));
            }
        }

        if let Some(max_recv_records_online) = max_recv_records_online {
            if max_recv_records_online > self.max_recv_records_online {
                return Err(ProtocolConfigError::max_record_count(format!(
                    "max_recv_records_online {} is greater than the configured limit {}",
                    max_recv_records_online, self.max_recv_records_online,
                )));
            }
        }

        Ok(())
    }

    // Checks if both versions are the same (might support check for different but
    // compatible versions in the future).
    fn check_version(&self, peer_version: &Version) -> Result<(), ProtocolConfigError> {
        if *peer_version != self.version {
            return Err(ProtocolConfigError::version(format!(
                "prover's version {:?} is different from verifier's version {:?}",
                peer_version, self.version
            )));
        }

        Ok(())
    }
}

/// Settings for the network environment.
///
/// Provides optimization options to adapt the protocol to different network
/// situations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NetworkSetting {
    /// Prefers a bandwidth-heavy protocol.
    Bandwidth,
    /// Prefers a latency-heavy protocol.
    Latency,
}

impl Default for NetworkSetting {
    fn default() -> Self {
        Self::Bandwidth
    }
}

/// A ProtocolConfig error.
#[derive(thiserror::Error, Debug)]
pub struct ProtocolConfigError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ProtocolConfigError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }

    fn max_transcript_size(msg: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::MaxTranscriptSize,
            source: Some(msg.into().into()),
        }
    }

    fn max_record_count(msg: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::MaxRecordCount,
            source: Some(msg.into().into()),
        }
    }

    fn version(msg: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Version,
            source: Some(msg.into().into()),
        }
    }
}

impl fmt::Display for ProtocolConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::MaxTranscriptSize => write!(f, "max transcript size exceeded")?,
            ErrorKind::MaxRecordCount => write!(f, "max record count exceeded")?,
            ErrorKind::Version => write!(f, "version error")?,
        }

        if let Some(ref source) = self.source {
            write!(f, " caused by: {source}")?;
        }

        Ok(())
    }
}

#[derive(Debug)]
enum ErrorKind {
    MaxTranscriptSize,
    MaxRecordCount,
    Version,
}

/// Configuration to prove information to the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveConfig {
    server_identity: bool,
    transcript: Option<PartialTranscript>,
    transcript_commit: Option<TranscriptCommitConfig>,
}

impl ProveConfig {
    /// Creates a new builder.
    pub fn builder(transcript: &Transcript) -> ProveConfigBuilder<'_> {
        ProveConfigBuilder::new(transcript)
    }

    /// Returns `true` if the server identity is to be proven.
    pub fn server_identity(&self) -> bool {
        self.server_identity
    }

    /// Returns the transcript to be proven.
    pub fn transcript(&self) -> Option<&PartialTranscript> {
        self.transcript.as_ref()
    }

    /// Returns the transcript commitment configuration.
    pub fn transcript_commit(&self) -> Option<&TranscriptCommitConfig> {
        self.transcript_commit.as_ref()
    }
}

/// Builder for [`ProveConfig`].
#[derive(Debug)]
pub struct ProveConfigBuilder<'a> {
    transcript: &'a Transcript,
    server_identity: bool,
    reveal_sent: Idx,
    reveal_recv: Idx,
    transcript_commit: Option<TranscriptCommitConfig>,
}

impl<'a> ProveConfigBuilder<'a> {
    /// Creates a new builder.
    pub fn new(transcript: &'a Transcript) -> Self {
        Self {
            transcript,
            server_identity: false,
            reveal_sent: Idx::default(),
            reveal_recv: Idx::default(),
            transcript_commit: None,
        }
    }

    /// Proves the server identity.
    pub fn server_identity(&mut self) -> &mut Self {
        self.server_identity = true;
        self
    }

    /// Configures transcript commitments.
    pub fn transcript_commit(&mut self, transcript_commit: TranscriptCommitConfig) -> &mut Self {
        self.transcript_commit = Some(transcript_commit);
        self
    }

    /// Reveals the given ranges of the transcript.
    pub fn reveal(
        &mut self,
        direction: Direction,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigBuilderError> {
        let idx = Idx::new(ranges.to_range_set());

        if idx.end() > self.transcript.len_of_direction(direction) {
            return Err(ProveConfigBuilderError(
                ProveConfigBuilderErrorRepr::IndexOutOfBounds {
                    direction,
                    actual: idx.end(),
                    len: self.transcript.len_of_direction(direction),
                },
            ));
        }

        match direction {
            Direction::Sent => self.reveal_sent.union_mut(&idx),
            Direction::Received => self.reveal_recv.union_mut(&idx),
        }
        Ok(self)
    }

    /// Reveals the given ranges of the sent data transcript.
    pub fn reveal_sent(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigBuilderError> {
        self.reveal(Direction::Sent, ranges)
    }

    /// Reveals the given ranges of the received data transcript.
    pub fn reveal_recv(
        &mut self,
        ranges: &dyn ToRangeSet<usize>,
    ) -> Result<&mut Self, ProveConfigBuilderError> {
        self.reveal(Direction::Received, ranges)
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProveConfig, ProveConfigBuilderError> {
        let transcript = if !self.reveal_sent.is_empty() || !self.reveal_recv.is_empty() {
            Some(
                self.transcript
                    .to_partial(self.reveal_sent, self.reveal_recv),
            )
        } else {
            None
        };

        Ok(ProveConfig {
            server_identity: self.server_identity,
            transcript,
            transcript_commit: self.transcript_commit,
        })
    }
}

/// Error for [`ProveConfigBuilder`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProveConfigBuilderError(#[from] ProveConfigBuilderErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ProveConfigBuilderErrorRepr {
    #[error("range is out of bounds of the transcript ({direction}): {actual} > {len}")]
    IndexOutOfBounds {
        direction: Direction,
        actual: usize,
        len: usize,
    },
}

/// Configuration to verify information from the prover.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VerifyConfig {}

impl VerifyConfig {
    /// Creates a new builder.
    pub fn builder() -> VerifyConfigBuilder {
        VerifyConfigBuilder::new()
    }
}

/// Builder for [`VerifyConfig`].
#[derive(Debug, Default)]
pub struct VerifyConfigBuilder {}

impl VerifyConfigBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {}
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<VerifyConfig, VerifyConfigBuilderError> {
        Ok(VerifyConfig {})
    }
}

/// Error for [`VerifyConfigBuilder`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct VerifyConfigBuilderError(#[from] VerifyConfigBuilderErrorRepr);

#[derive(Debug, thiserror::Error)]
enum VerifyConfigBuilderErrorRepr {}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::{fixture, rstest};

    const TEST_MAX_SENT_LIMIT: usize = 1 << 12;
    const TEST_MAX_RECV_LIMIT: usize = 1 << 14;

    #[fixture]
    #[once]
    fn config_validator() -> ProtocolConfigValidator {
        ProtocolConfigValidator::builder()
            .max_sent_data(TEST_MAX_SENT_LIMIT)
            .max_recv_data(TEST_MAX_RECV_LIMIT)
            .build()
            .unwrap()
    }

    #[rstest]
    #[case::same_max_sent_recv_data(TEST_MAX_SENT_LIMIT, TEST_MAX_RECV_LIMIT)]
    #[case::smaller_max_sent_data(1 << 11, TEST_MAX_RECV_LIMIT)]
    #[case::smaller_max_recv_data(TEST_MAX_SENT_LIMIT, 1 << 13)]
    #[case::smaller_max_sent_recv_data(1 << 7, 1 << 9)]
    fn test_check_success(
        config_validator: &ProtocolConfigValidator,
        #[case] max_sent_data: usize,
        #[case] max_recv_data: usize,
    ) {
        let peer_config = ProtocolConfig::builder()
            .max_sent_data(max_sent_data)
            .max_recv_data(max_recv_data)
            .build()
            .unwrap();

        assert!(config_validator.validate(&peer_config).is_ok())
    }

    #[rstest]
    #[case::bigger_max_sent_data(1 << 13, TEST_MAX_RECV_LIMIT)]
    #[case::bigger_max_recv_data(1 << 10, 1 << 16)]
    #[case::bigger_max_sent_recv_data(1 << 14, 1 << 21)]
    fn test_check_fail(
        config_validator: &ProtocolConfigValidator,
        #[case] max_sent_data: usize,
        #[case] max_recv_data: usize,
    ) {
        let peer_config = ProtocolConfig::builder()
            .max_sent_data(max_sent_data)
            .max_recv_data(max_recv_data)
            .build()
            .unwrap();

        assert!(config_validator.validate(&peer_config).is_err())
    }
}
