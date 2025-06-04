use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const DEFAULT_PROTOCOL_LATENCY: usize = 50;
pub const DEFAULT_APP_LATENCY: usize = 50;
pub const DEFAULT_BANDWIDTH: usize = 1000;
pub const DEFAULT_UPLOAD_SIZE: usize = 1024;
pub const DEFAULT_DOWNLOAD_SIZE: usize = 4096;
pub const DEFAULT_DEFER_DECRYPTION: bool = true;
pub const DEFAULT_MEMORY_PROFILE: bool = false;

pub const WARM_UP_BENCH: Bench = Bench {
    group: None,
    name: None,
    protocol_latency: 1,
    app_latency: 1,
    bandwidth: 1000,
    upload_size: 1024,
    download_size: 4096,
    defer_decryption: true,
    memory_profile: false,
};

#[derive(Deserialize)]
pub struct BenchItems {
    pub group: Vec<BenchGroupItem>,
    pub bench: Vec<BenchItem>,
}

impl BenchItems {
    pub fn to_benches(&self, samples: usize, samples_override: bool) -> Vec<Bench> {
        let group: HashMap<String, BenchGroupItem> = HashMap::from_iter(
            self.group
                .iter()
                .cloned()
                .map(|group| (group.name.clone(), group)),
        );

        let mut benches = Vec::new();
        for mut bench in self.bench.clone() {
            if let Some(group_name) = &bench.group {
                let group = group
                    .get(group_name)
                    .expect("bench group should be defined: {group_name}");
                bench.apply_group(group);
            }

            let count = if samples_override {
                samples
            } else if let Some(samples) = bench.samples {
                samples
            } else {
                samples
            };

            for _ in 0..count {
                benches.push(bench.into_bench());
            }
        }

        benches.sort_by_key(|bench| (bench.group.clone(), bench.name.clone()));
        benches
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchGroupItem {
    pub name: String,
    pub samples: Option<usize>,
    pub latency: Option<usize>,
    pub bandwidth: Option<usize>,
    #[serde(rename = "upload-size")]
    pub upload_size: Option<usize>,
    #[serde(rename = "download-size")]
    pub download_size: Option<usize>,
    #[serde(rename = "defer-decryption")]
    pub defer_decryption: Option<bool>,
    #[serde(rename = "memory-profile")]
    pub memory_profile: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchItem {
    pub group: Option<String>,
    pub name: Option<String>,
    pub samples: Option<usize>,
    pub protocol_latency: Option<usize>,
    pub app_latency: Option<usize>,
    pub bandwidth: Option<usize>,
    #[serde(rename = "upload-size")]
    pub upload_size: Option<usize>,
    #[serde(rename = "download-size")]
    pub download_size: Option<usize>,
    #[serde(rename = "defer-decryption")]
    pub defer_decryption: Option<bool>,
    #[serde(rename = "memory-profile")]
    pub memory_profile: Option<bool>,
}

impl BenchItem {
    pub fn apply_group(&mut self, group: &BenchGroupItem) {
        if self.samples.is_none() {
            self.samples = group.samples;
        }

        if self.protocol_latency.is_none() {
            self.protocol_latency = group.latency;
        }

        if self.bandwidth.is_none() {
            self.bandwidth = group.bandwidth;
        }

        if self.upload_size.is_none() {
            self.upload_size = group.upload_size;
        }

        if self.download_size.is_none() {
            self.download_size = group.download_size;
        }

        if self.defer_decryption.is_none() {
            self.defer_decryption = group.defer_decryption;
        }

        if self.memory_profile.is_none() {
            self.memory_profile = group.memory_profile;
        }
    }

    pub fn into_bench(&self) -> Bench {
        Bench {
            group: self.group.clone(),
            name: self.name.clone(),
            protocol_latency: self.protocol_latency.unwrap_or(DEFAULT_PROTOCOL_LATENCY),
            app_latency: self.app_latency.unwrap_or(DEFAULT_APP_LATENCY),
            bandwidth: self.bandwidth.unwrap_or(DEFAULT_BANDWIDTH),
            upload_size: self.upload_size.unwrap_or(DEFAULT_UPLOAD_SIZE),
            download_size: self.download_size.unwrap_or(DEFAULT_DOWNLOAD_SIZE),
            defer_decryption: self.defer_decryption.unwrap_or(DEFAULT_DEFER_DECRYPTION),
            memory_profile: self.memory_profile.unwrap_or(DEFAULT_MEMORY_PROFILE),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bench {
    pub group: Option<String>,
    pub name: Option<String>,
    pub protocol_latency: usize,
    pub app_latency: usize,
    pub bandwidth: usize,
    #[serde(rename = "upload-size")]
    pub upload_size: usize,
    #[serde(rename = "download-size")]
    pub download_size: usize,
    #[serde(rename = "defer-decryption")]
    pub defer_decryption: bool,
    #[serde(rename = "memory-profile")]
    pub memory_profile: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BenchOutput {
    Prover { metrics: ProverMetrics },
    Verifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverMetrics {
    /// Time taken to preprocess the connection in seconds.
    pub time_preprocess: u64,
    /// TLS connection online time in seconds.
    pub time_online: u64,
    /// Total runtime of the benchmark in seconds.
    pub time_total: u64,
    /// Total amount of data uploaded to the verifier in bytes during
    /// preprocessing.
    pub uploaded_preprocess: u64,
    /// Total amount of data downloaded from the verifier in bytes during
    /// preprocessing.
    pub downloaded_preprocess: u64,
    /// Total amount of data uploaded to the verifier in bytes during online
    /// phase.
    pub uploaded_online: u64,
    /// Total amount of data downloaded from the verifier in bytes during online
    /// phase.
    pub downloaded_online: u64,
    /// Total amount of data uploaded to the verifier in bytes.
    pub uploaded_total: u64,
    /// Total amount of data downloaded from the verifier in bytes.
    pub downloaded_total: u64,
    /// Peak heap memory usage in bytes.
    pub heap_max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurement {
    pub group: Option<String>,
    pub name: Option<String>,
    pub latency: usize,
    pub bandwidth: usize,
    pub upload_size: usize,
    pub download_size: usize,
    pub defer_decryption: bool,
    /// Time taken to preprocess the connection in seconds.
    pub time_preprocess: u64,
    /// TLS connection online time in seconds.
    pub time_online: u64,
    /// Total runtime of the benchmark in seconds.
    pub time_total: u64,
    /// Total amount of data uploaded to the verifier in bytes during
    /// preprocessing.
    pub uploaded_preprocess: u64,
    /// Total amount of data downloaded from the verifier in bytes during
    /// preprocessing.
    pub downloaded_preprocess: u64,
    /// Total amount of data uploaded to the verifier in bytes during online
    /// phase.
    pub uploaded_online: u64,
    /// Total amount of data downloaded from the verifier in bytes during online
    /// phase.
    pub downloaded_online: u64,
    /// Total amount of data uploaded to the verifier in bytes.
    pub uploaded_total: u64,
    /// Total amount of data downloaded from the verifier in bytes.
    pub downloaded_total: u64,
    /// Peak heap memory usage in bytes.
    pub heap_max_bytes: Option<usize>,
}

impl Measurement {
    pub fn new(config: Bench, metrics: ProverMetrics) -> Self {
        Self {
            group: config.group,
            name: config.name,
            latency: config.protocol_latency,
            bandwidth: config.bandwidth,
            upload_size: config.upload_size,
            download_size: config.download_size,
            defer_decryption: config.defer_decryption,
            time_preprocess: metrics.time_preprocess,
            time_online: metrics.time_online,
            time_total: metrics.time_total,
            uploaded_preprocess: metrics.uploaded_preprocess,
            downloaded_preprocess: metrics.downloaded_preprocess,
            uploaded_online: metrics.uploaded_online,
            downloaded_online: metrics.downloaded_online,
            uploaded_total: metrics.uploaded_total,
            downloaded_total: metrics.downloaded_total,
            heap_max_bytes: metrics.heap_max_bytes,
        }
    }
}
