use serde::Deserialize;
use tsify::Tsify;

#[derive(Debug, Tsify, Deserialize)]
pub struct VerifierConfig {
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub max_sent_records: Option<usize>,
    pub max_recv_records_online: Option<usize>,
    /// Custom root certificates (DER-encoded) for TLS server verification.
    ///
    /// If not provided, Mozilla root certificates are used.
    pub root_certs: Option<Vec<Vec<u8>>>,
}
