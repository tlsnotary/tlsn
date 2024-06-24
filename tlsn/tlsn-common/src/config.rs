//! TLSNotary protocol config and config utilities.
use core::fmt;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::Role;

/// Default for the maximum number of bytes that can be sent (4Kb).
pub const DEFAULT_MAX_SENT_LIMIT: usize = 1 << 12;
/// Default for the maximum number of bytes that can be received (16Kb).
pub const DEFAULT_MAX_RECV_LIMIT: usize = 1 << 14;

// Determined experimentally, will be subject to change if underlying protocols are modified.
const KE_OTS: usize = 3360;
// Secret-sharing the GHASH blocks.
const GHASH_OTS: usize = 65664 * 2;
// Extra cushion room, eg. for sharing J0 blocks.
const EXTRA_OTS: usize = 16384;
const OTS_PER_BYTE_SENT: usize = 8;
// Without deferred decryption we use 16, with it we use 8.
const OTS_PER_BYTE_RECV: usize = 16;

// Current version that is running.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Configuration info to be exchanged initially between prover and verifier for compatibility check.
#[derive(derive_builder::Builder, Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ConfigurationInfo {
    /// Maximum number of bytes that can be sent.
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data: usize,
    /// Maximum number of bytes that can be received.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_recv_data: usize,
    /// Version that is being run by prover/verifier.
    #[builder(setter(skip), default = "VERSION.to_string()")]
    version: String,
}

impl ConfigurationInfo {
    /// Creates a new builder for `ConfigurationInfo`.
    pub fn builder() -> ConfigurationInfoBuilder {
        ConfigurationInfoBuilder::default()
    }

    /// Returns the maximum number of bytes that can be sent.
    pub fn max_sent_data(&self) -> usize {
        self.max_sent_data
    }

    /// Returns the maximum number of bytes that can be received.
    pub fn max_recv_data(&self) -> usize {
        self.max_recv_data
    }

    /// Performs compatibility check of the configuration info between prover and verifier.
    pub fn compare(&self, configuration: &Self) -> Result<(), ConfigurationError> {
        self.check_max_transcript_size(configuration.max_sent_data, configuration.max_recv_data)?;
        self.check_version(&configuration.version)?;
        Ok(())
    }

    // Checks if both the sent and recv limits are the same.
    fn check_max_transcript_size(
        &self,
        max_sent_data: usize,
        max_recv_data: usize,
    ) -> Result<(), ConfigurationError> {
        if max_sent_data != self.max_sent_data {
            return Err(ConfigurationError::max_transcript_size(
                "prover and verifier have different max_sent_data configured",
            ));
        }

        if max_recv_data != self.max_recv_data {
            return Err(ConfigurationError::max_transcript_size(
                "prover and verifier have different max_recv_data configured",
            ));
        }

        Ok(())
    }

    // Checks if both versions are the same (might support check for different but compatible versions in the future).
    fn check_version(&self, version: &str) -> Result<(), ConfigurationError> {
        let self_version = Version::parse(&self.version)
            .map_err(|err| ConfigurationError::new(ErrorKind::Version, err))?;

        let peer_version = Version::parse(version)
            .map_err(|err| ConfigurationError::new(ErrorKind::Version, err))?;

        if peer_version != self_version {
            return Err(ConfigurationError::version(
                "prover and verifier are running different versions",
            ));
        }

        Ok(())
    }
}

/// A Configuration error.
#[derive(thiserror::Error, Debug)]
pub struct ConfigurationError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl ConfigurationError {
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

impl fmt::Display for ConfigurationError {
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
pub fn ot_send_estimate(role: Role, max_sent_data: usize, max_recv_data: usize) -> usize {
    match role {
        Role::Prover => KE_OTS + GHASH_OTS + EXTRA_OTS,
        Role::Verifier => {
            KE_OTS
                + EXTRA_OTS
                + (max_sent_data * OTS_PER_BYTE_SENT)
                + (max_recv_data * OTS_PER_BYTE_RECV)
        }
    }
}

/// Returns an estimate of the number of OTs that will be received.
pub fn ot_recv_estimate(role: Role, max_sent_data: usize, max_recv_data: usize) -> usize {
    match role {
        Role::Prover => {
            KE_OTS
                + EXTRA_OTS
                + (max_sent_data * OTS_PER_BYTE_SENT)
                + (max_recv_data * OTS_PER_BYTE_RECV)
        }
        Role::Verifier => KE_OTS + GHASH_OTS + EXTRA_OTS,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    #[once]
    fn self_config() -> ConfigurationInfo {
        ConfigurationInfo::builder().build().unwrap()
    }

    #[rstest]
    fn test_check_success(self_config: &ConfigurationInfo) {
        let peer_config = ConfigurationInfo::builder().build().unwrap();
        assert!(self_config.compare(&peer_config).is_ok())
    }

    #[rstest]
    #[case::diff_max_sent_data(1 << 11, DEFAULT_MAX_RECV_LIMIT)]
    #[case::diff_max_recv_data(DEFAULT_MAX_SENT_LIMIT, 1 << 11)]
    #[case::diff_max_sent_recv_data(1 << 10, 1 << 11)]
    fn test_check_fail(
        self_config: &ConfigurationInfo,
        #[case] max_sent_data: usize,
        #[case] max_recv_data: usize,
    ) {
        let peer_config = ConfigurationInfo::builder()
            .max_sent_data(max_sent_data)
            .max_recv_data(max_recv_data)
            .build()
            .unwrap();

        assert!(self_config.compare(&peer_config).is_err())
    }
}
