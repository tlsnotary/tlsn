use tls_core::{suites::SupportedCipherSuite, versions::SupportedProtocolVersion};

use crate::commitment::CommitmentScheme;

pub struct CommonSessionConfig {
    supported_tls_versions: Vec<SupportedProtocolVersion>,
    supported_suites: Vec<SupportedCipherSuite>,
    commitment_scheme: CommitmentScheme,
}
