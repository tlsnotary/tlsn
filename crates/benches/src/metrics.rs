use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub name: String,
    /// Upload bandwidth in Mbps.
    pub upload: usize,
    /// Upload latency in ms.
    pub upload_delay: usize,
    /// Download bandwidth in Mbps.
    pub download: usize,
    /// Download latency in ms.
    pub download_delay: usize,
    /// Total bytes sent to the server.
    pub upload_size: usize,
    /// Total bytes received from the server.
    pub download_size: usize,
    /// Whether deferred decryption was used.
    pub defer_decryption: bool,
    /// The total runtime of the benchmark in seconds.
    pub runtime: u64,
    /// The total amount of data uploaded to the verifier in bytes.
    pub uploaded: u64,
    /// The total amount of data downloaded from the verifier in bytes.
    pub downloaded: u64,
}
