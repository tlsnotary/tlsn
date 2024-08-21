//! TLSNotary protocol config and config utilities.
use core::fmt;
use once_cell::sync::Lazy;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::Role;

/// Default for the maximum number of bytes that can be sent (4KB).
pub const DEFAULT_MAX_SENT_LIMIT: usize = 1 << 12;
/// Default for the maximum number of bytes that can be received (16KB).
pub const DEFAULT_MAX_RECV_LIMIT: usize = 1 << 14;

// Extra cushion room, eg. for sharing J0 blocks.
const EXTRA_OTS: usize = 16384;

const OTS_PER_BYTE_SENT: usize = 8;

// Without deferred decryption we use 16, with it we use 8.
const OTS_PER_BYTE_RECV_ONLINE: usize = 16;
const OTS_PER_BYTE_RECV_DEFER: usize = 8;

// Current version that is running.
static VERSION: Lazy<Version> = Lazy::new(|| {
    Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|err| ProtocolConfigError::new(ErrorKind::Version, err))
        .unwrap()
});

/// Protocol configuration to be set up initially by prover and verifier.
#[derive(derive_builder::Builder, Clone, Debug, Deserialize, Serialize)]
pub struct ProtocolConfig {
    /// Maximum number of bytes that can be sent.
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data: usize,
    /// Maximum number of bytes that can be decrypted online.
    #[builder(default = "0")]
    max_recv_data_online: usize,
    /// Maximum number of bytes that will be decrypted after the TLS connection is closed.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_deferred_size: usize,
    /// Version that is being run by prover/verifier.
    #[builder(setter(skip), default = "VERSION.clone()")]
    version: Version,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self::builder().build().unwrap()
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

    /// Returns the maximum number of bytes that can be decrypted online.
    pub fn max_recv_data_online(&self) -> usize {
        self.max_recv_data_online
    }

    /// Returns the maximum number of bytes that will be decrypted after the TLS connection is closed.
    pub fn max_deferred_size(&self) -> usize {
        self.max_deferred_size
    }

    /// Returns OT sender setup count.
    pub fn ot_sender_setup_count(&self, role: Role) -> usize {
        ot_send_estimate(
            role,
            self.max_sent_data,
            self.max_recv_data_online,
            self.max_deferred_size,
        )
    }

    /// Returns OT receiver setup count.
    pub fn ot_receiver_setup_count(&self, role: Role) -> usize {
        ot_recv_estimate(
            role,
            self.max_sent_data,
            self.max_recv_data_online,
            self.max_deferred_size,
        )
    }
}

/// Protocol configuration validator used by checker (i.e. verifier) to perform compatibility check
/// with the peer's (i.e. the prover's) configuration.
#[derive(derive_builder::Builder, Clone, Debug)]
pub struct ProtocolConfigValidator {
    /// Maximum number of bytes that can be sent.
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data: usize,
    /// Maximum number of bytes that can be received.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_recv_data: usize,
    /// Version that is being run by checker.
    #[builder(setter(skip), default = "VERSION.clone()")]
    version: Version,
}

impl Default for ProtocolConfigValidator {
    fn default() -> Self {
        Self::builder().build().unwrap()
    }
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

    /// Returns the maximum number of bytes that can be received.
    pub fn max_recv_data(&self) -> usize {
        self.max_recv_data
    }

    /// Performs compatibility check of the protocol configuration between prover and verifier.
    pub fn validate(&self, config: &ProtocolConfig) -> Result<(), ProtocolConfigError> {
        self.check_max_transcript_size(
            config.max_sent_data,
            config.max_recv_data_online,
            config.max_deferred_size,
        )?;
        self.check_version(&config.version)?;
        Ok(())
    }

    // Checks if both the sent and recv data are within limits.
    fn check_max_transcript_size(
        &self,
        max_sent_data: usize,
        max_recv_data_online: usize,
        max_deferred_size: usize,
    ) -> Result<(), ProtocolConfigError> {
        if max_sent_data > self.max_sent_data {
            return Err(ProtocolConfigError::max_transcript_size(format!(
                "max_sent_data {:?} is greater than the configured limit {:?}",
                max_sent_data, self.max_sent_data,
            )));
        }

        if max_recv_data_online + max_deferred_size > self.max_recv_data {
            return Err(ProtocolConfigError::max_transcript_size(format!(
                "max_recv_data {:?} is greater than the configured limit {:?}",
                max_recv_data_online + max_deferred_size,
                self.max_recv_data,
            )));
        }

        Ok(())
    }

    // Checks if both versions are the same (might support check for different but compatible versions in the future).
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
            ErrorKind::MaxTranscriptSize => write!(f, "max transcript size error")?,
            ErrorKind::Version => write!(f, "version error")?,
        }

        if let Some(ref source) = self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
enum ErrorKind {
    MaxTranscriptSize,
    Version,
}

/// Returns an estimate of the number of OTs that will be sent.
pub fn ot_send_estimate(
    role: Role,
    max_sent_data: usize,
    max_recv_data_online: usize,
    max_deferred_size: usize,
) -> usize {
    match role {
        Role::Prover => EXTRA_OTS,
        Role::Verifier => {
            EXTRA_OTS
                + (max_sent_data * OTS_PER_BYTE_SENT)
                + (max_recv_data_online * OTS_PER_BYTE_RECV_ONLINE)
                + (max_deferred_size * OTS_PER_BYTE_RECV_DEFER)
        }
    }
}

/// Returns an estimate of the number of OTs that will be received.
pub fn ot_recv_estimate(
    role: Role,
    max_sent_data: usize,
    max_recv_data_online: usize,
    max_deferred_size: usize,
) -> usize {
    match role {
        Role::Prover => {
            EXTRA_OTS
                + (max_sent_data * OTS_PER_BYTE_SENT)
                + (max_recv_data_online * OTS_PER_BYTE_RECV_ONLINE)
                + (max_deferred_size * OTS_PER_BYTE_RECV_DEFER)
        }
        Role::Verifier => EXTRA_OTS,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    #[once]
    fn config_validator() -> ProtocolConfigValidator {
        ProtocolConfigValidator::builder().build().unwrap()
    }

    #[rstest]
    #[case::same_max_sent_recv_data(DEFAULT_MAX_SENT_LIMIT, DEFAULT_MAX_RECV_LIMIT)]
    #[case::smaller_max_sent_data(1 << 11, DEFAULT_MAX_RECV_LIMIT)]
    #[case::smaller_max_recv_data(DEFAULT_MAX_SENT_LIMIT, 1 << 13)]
    #[case::smaller_max_sent_recv_data(1 << 7, 1 << 9)]
    fn test_check_success(
        config_validator: &ProtocolConfigValidator,
        #[case] max_sent_data: usize,
        #[case] max_recv_data: usize,
    ) {
        let peer_config = ProtocolConfig::builder()
            .max_sent_data(max_sent_data)
            .max_recv_data_online(max_recv_data)
            .build()
            .unwrap();

        assert!(config_validator.validate(&peer_config).is_ok())
    }

    #[rstest]
    #[case::bigger_max_sent_data(1 << 13, DEFAULT_MAX_RECV_LIMIT)]
    #[case::bigger_max_recv_data(1 << 10, 1 << 16)]
    #[case::bigger_max_sent_recv_data(1 << 14, 1 << 21)]
    fn test_check_fail(
        config_validator: &ProtocolConfigValidator,
        #[case] max_sent_data: usize,
        #[case] max_recv_data: usize,
    ) {
        let peer_config = ProtocolConfig::builder()
            .max_sent_data(max_sent_data)
            .max_recv_data_online(max_recv_data)
            .build()
            .unwrap();

        assert!(config_validator.validate(&peer_config).is_err())
    }
}
