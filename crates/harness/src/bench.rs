mod io;
mod prover;
mod verifier;

pub(crate) use io::Meter;
pub use prover::bench_prover;
pub use verifier::bench_verifier;

use serde::{Deserialize, Serialize};

/// Transcript size padding to account for HTTP framing.
pub(crate) const PADDING: usize = 256;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Field<T> {
    Single(T),
    Multiple(Vec<T>),
}

#[derive(Deserialize)]
pub struct Config {
    pub benches: Vec<BenchItem>,
}

#[derive(Deserialize)]
pub struct BenchItem {
    pub name: String,
    pub latency: Field<usize>,
    pub upload: Field<usize>,
    pub download: Field<usize>,
    #[serde(rename = "upload-size")]
    pub upload_size: Field<usize>,
    #[serde(rename = "download-size")]
    pub download_size: Field<usize>,
    #[serde(rename = "defer-decryption")]
    pub defer_decryption: Field<bool>,
    #[serde(rename = "memory-profile")]
    pub memory_profile: Field<bool>,
}

impl BenchItem {
    /// Flattens the config into a list of instances
    pub fn flatten(self) -> Vec<BenchConfig> {
        let mut instances = vec![];

        let latency = match self.latency {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let upload = match self.upload {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let download = match self.download {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let upload_size = match self.upload_size {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let download_size = match self.download_size {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let defer_decryption = match self.defer_decryption {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        let memory_profile = match self.memory_profile {
            Field::Single(u) => vec![u],
            Field::Multiple(u) => u,
        };

        for latency in latency {
            for u in &upload {
                for d in &download {
                    for us in &upload_size {
                        for ds in &download_size {
                            for dd in &defer_decryption {
                                for mp in &memory_profile {
                                    instances.push(BenchConfig {
                                        name: self.name.clone(),
                                        latency,
                                        upload: *u,
                                        download: *d,
                                        upload_size: *us,
                                        download_size: *ds,
                                        defer_decryption: *dd,
                                        memory_profile: *mp,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        instances
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserBenchConfig {
    pub proxy_addr: (String, u16),
    pub verifier_addr: (String, u16),
    pub server_addr: (String, u16),
    pub bench: BenchConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchConfig {
    pub name: String,
    pub latency: usize,
    pub upload: usize,
    pub download: usize,
    pub upload_size: usize,
    pub download_size: usize,
    pub defer_decryption: bool,
    /// Whether this instance should be used for memory profiling.
    pub memory_profile: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Time taken to preprocess the connection in seconds.
    pub time_preprocess: u64,
    /// TLS connection online time in seconds.
    pub time_online: u64,
    /// Total runtime of the benchmark in seconds.
    pub time_total: u64,
    /// Total amount of data uploaded to the verifier in bytes.
    pub uploaded: u64,
    /// Total amount of data downloaded from the verifier in bytes.
    pub downloaded: u64,
    /// Peak heap memory usage in bytes.
    pub heap_max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurement {
    pub name: String,
    pub latency: usize,
    pub upload: usize,
    pub download: usize,
    pub upload_size: usize,
    pub download_size: usize,
    pub defer_decryption: bool,
    /// Time taken to preprocess the connection in seconds.
    pub time_preprocess: u64,
    /// TLS connection online time in seconds.
    pub time_online: u64,
    /// Total runtime of the benchmark in seconds.
    pub time_total: u64,
    /// Total amount of data uploaded to the verifier in bytes.
    pub uploaded: u64,
    /// Total amount of data downloaded from the verifier in bytes.
    pub downloaded: u64,
    /// Peak heap memory usage in bytes.
    pub heap_max_bytes: Option<usize>,
}

impl Measurement {
    pub fn new(config: BenchConfig, metrics: Metrics) -> Self {
        Self {
            name: config.name,
            latency: config.latency,
            upload: config.upload,
            download: config.download,
            upload_size: config.upload_size,
            download_size: config.download_size,
            defer_decryption: config.defer_decryption,
            time_preprocess: metrics.time_preprocess,
            time_online: metrics.time_online,
            time_total: metrics.time_total,
            uploaded: metrics.uploaded,
            downloaded: metrics.downloaded,
            heap_max_bytes: metrics.heap_max_bytes,
        }
    }
}

/// Calculates burst rate in bps.
pub(crate) fn burst(rate: usize) -> usize {
    // 2ms burst.
    rate * 2 / 1000
}
