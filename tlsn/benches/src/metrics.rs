use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Metrics {
    pub name: String,
    pub upload: usize,
    pub upload_delay: usize,
    pub download: usize,
    pub download_delay: usize,
    pub upload_size: usize,
    pub download_size: usize,
    pub defer_decryption: bool,
    /// The total runtime of the benchmark in seconds.
    pub runtime: u64,
    /// The total amount of data uploaded to the verifier in bytes.
    pub uploaded: u64,
    /// The total amount of data downloaded from the verifier in bytes.
    pub downloaded: u64,
}
