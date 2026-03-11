use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const DEFAULT_PROTOCOL_LATENCY: usize = 50;
pub const DEFAULT_APP_LATENCY: usize = 50;
pub const DEFAULT_BANDWIDTH: usize = 1000;
pub const DEFAULT_UPLOAD_SIZE: usize = 1024;
pub const DEFAULT_DOWNLOAD_SIZE: usize = 4096;
pub const DEFAULT_DEFER_DECRYPTION: bool = true;
pub const DEFAULT_MEMORY_PROFILE: bool = false;
pub const DEFAULT_REVEAL_ALL: bool = false;

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
    reveal_all: true,
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
    #[serde(rename = "reveal-all")]
    pub reveal_all: Option<bool>,
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
    #[serde(rename = "reveal-all")]
    pub reveal_all: Option<bool>,
}

impl BenchItem {
    pub fn apply_group(&mut self, group: &BenchGroupItem) {
        if self.samples.is_none() {
            self.samples = group.samples;
        }

        if self.protocol_latency.is_none() {
            self.protocol_latency = group.protocol_latency;
        }

        if self.app_latency.is_none() {
            self.app_latency = group.app_latency;
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

        if self.reveal_all.is_none() {
            self.reveal_all = group.reveal_all;
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
            reveal_all: self.reveal_all.unwrap_or(DEFAULT_REVEAL_ALL),
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
    #[serde(rename = "reveal-all")]
    pub reveal_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BenchOutput {
    Prover { metrics: ProverMetrics },
    Verifier,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PhaseMetrics {
    // Named phase totals are intentionally partial and do not sum to the
    // coarse runtime totals. Control-plane exchanges and other orchestration
    // overhead remain visible only in the coarse metrics.
    #[serde(default)]
    pub phase_preprocess_setup_count: u64,
    #[serde(default)]
    pub phase_preprocess_setup_time_ms: u64,
    #[serde(default)]
    pub phase_preprocess_setup_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_preprocess_setup_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_preprocess_setup_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_preprocess_setup_io_wait_write_ms: u64,
    #[serde(default)]
    pub phase_handshake_ke_online_count: u64,
    #[serde(default)]
    pub phase_handshake_ke_online_time_ms: u64,
    #[serde(default)]
    pub phase_handshake_ke_online_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_ke_online_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_ke_online_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_handshake_ke_online_io_wait_write_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_session_keys_count: u64,
    #[serde(default)]
    pub phase_handshake_prf_session_keys_time_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_session_keys_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_prf_session_keys_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_prf_session_keys_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_session_keys_io_wait_write_ms: u64,
    #[serde(default)]
    pub phase_handshake_record_setup_count: u64,
    #[serde(default)]
    pub phase_handshake_record_setup_time_ms: u64,
    #[serde(default)]
    pub phase_handshake_record_setup_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_record_setup_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_record_setup_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_handshake_record_setup_io_wait_write_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_server_finished_count: u64,
    #[serde(default)]
    pub phase_handshake_prf_server_finished_time_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_server_finished_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_prf_server_finished_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_prf_server_finished_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_server_finished_io_wait_write_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_client_finished_count: u64,
    #[serde(default)]
    pub phase_handshake_prf_client_finished_time_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_client_finished_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_prf_client_finished_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_handshake_prf_client_finished_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_handshake_prf_client_finished_io_wait_write_ms: u64,
    #[serde(default)]
    pub phase_record_layer_flush_count: u64,
    #[serde(default)]
    pub phase_record_layer_flush_time_ms: u64,
    #[serde(default)]
    pub phase_record_layer_flush_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_record_layer_flush_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_record_layer_flush_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_record_layer_flush_io_wait_write_ms: u64,
    #[serde(default)]
    pub phase_finalize_tls_auth_count: u64,
    #[serde(default)]
    pub phase_finalize_tls_auth_time_ms: u64,
    #[serde(default)]
    pub phase_finalize_tls_auth_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_finalize_tls_auth_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_finalize_tls_auth_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_finalize_tls_auth_io_wait_write_ms: u64,
    #[serde(default)]
    pub phase_prove_transcript_count: u64,
    #[serde(default)]
    pub phase_prove_transcript_time_ms: u64,
    #[serde(default)]
    pub phase_prove_transcript_uploaded_bytes: u64,
    #[serde(default)]
    pub phase_prove_transcript_downloaded_bytes: u64,
    #[serde(default)]
    pub phase_prove_transcript_io_wait_read_ms: u64,
    #[serde(default)]
    pub phase_prove_transcript_io_wait_write_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ProverMetrics {
    /// Time taken to preprocess the connection in milliseconds.
    pub time_preprocess: u64,
    /// TLS connection online time in milliseconds.
    pub time_online: u64,
    /// Total runtime of the benchmark in milliseconds.
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
    pub phase_metrics: PhaseMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProverMetricsRecord {
    time_preprocess: u64,
    time_online: u64,
    time_total: u64,
    uploaded_preprocess: u64,
    downloaded_preprocess: u64,
    uploaded_online: u64,
    downloaded_online: u64,
    uploaded_total: u64,
    downloaded_total: u64,
    heap_max_bytes: Option<usize>,
    #[serde(default)]
    phase_preprocess_setup_count: u64,
    #[serde(default)]
    phase_preprocess_setup_time_ms: u64,
    #[serde(default)]
    phase_preprocess_setup_uploaded_bytes: u64,
    #[serde(default)]
    phase_preprocess_setup_downloaded_bytes: u64,
    #[serde(default)]
    phase_preprocess_setup_io_wait_read_ms: u64,
    #[serde(default)]
    phase_preprocess_setup_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_ke_online_count: u64,
    #[serde(default)]
    phase_handshake_ke_online_time_ms: u64,
    #[serde(default)]
    phase_handshake_ke_online_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_ke_online_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_ke_online_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_ke_online_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_count: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_time_ms: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_record_setup_count: u64,
    #[serde(default)]
    phase_handshake_record_setup_time_ms: u64,
    #[serde(default)]
    phase_handshake_record_setup_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_record_setup_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_record_setup_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_record_setup_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_count: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_time_ms: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_count: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_time_ms: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_io_wait_write_ms: u64,
    #[serde(default)]
    phase_record_layer_flush_count: u64,
    #[serde(default)]
    phase_record_layer_flush_time_ms: u64,
    #[serde(default)]
    phase_record_layer_flush_uploaded_bytes: u64,
    #[serde(default)]
    phase_record_layer_flush_downloaded_bytes: u64,
    #[serde(default)]
    phase_record_layer_flush_io_wait_read_ms: u64,
    #[serde(default)]
    phase_record_layer_flush_io_wait_write_ms: u64,
    #[serde(default)]
    phase_finalize_tls_auth_count: u64,
    #[serde(default)]
    phase_finalize_tls_auth_time_ms: u64,
    #[serde(default)]
    phase_finalize_tls_auth_uploaded_bytes: u64,
    #[serde(default)]
    phase_finalize_tls_auth_downloaded_bytes: u64,
    #[serde(default)]
    phase_finalize_tls_auth_io_wait_read_ms: u64,
    #[serde(default)]
    phase_finalize_tls_auth_io_wait_write_ms: u64,
    #[serde(default)]
    phase_prove_transcript_count: u64,
    #[serde(default)]
    phase_prove_transcript_time_ms: u64,
    #[serde(default)]
    phase_prove_transcript_uploaded_bytes: u64,
    #[serde(default)]
    phase_prove_transcript_downloaded_bytes: u64,
    #[serde(default)]
    phase_prove_transcript_io_wait_read_ms: u64,
    #[serde(default)]
    phase_prove_transcript_io_wait_write_ms: u64,
}

impl From<ProverMetrics> for ProverMetricsRecord {
    fn from(value: ProverMetrics) -> Self {
        let phase = value.phase_metrics;
        Self {
            time_preprocess: value.time_preprocess,
            time_online: value.time_online,
            time_total: value.time_total,
            uploaded_preprocess: value.uploaded_preprocess,
            downloaded_preprocess: value.downloaded_preprocess,
            uploaded_online: value.uploaded_online,
            downloaded_online: value.downloaded_online,
            uploaded_total: value.uploaded_total,
            downloaded_total: value.downloaded_total,
            heap_max_bytes: value.heap_max_bytes,
            phase_preprocess_setup_count: phase.phase_preprocess_setup_count,
            phase_preprocess_setup_time_ms: phase.phase_preprocess_setup_time_ms,
            phase_preprocess_setup_uploaded_bytes: phase.phase_preprocess_setup_uploaded_bytes,
            phase_preprocess_setup_downloaded_bytes: phase.phase_preprocess_setup_downloaded_bytes,
            phase_preprocess_setup_io_wait_read_ms: phase.phase_preprocess_setup_io_wait_read_ms,
            phase_preprocess_setup_io_wait_write_ms: phase.phase_preprocess_setup_io_wait_write_ms,
            phase_handshake_ke_online_count: phase.phase_handshake_ke_online_count,
            phase_handshake_ke_online_time_ms: phase.phase_handshake_ke_online_time_ms,
            phase_handshake_ke_online_uploaded_bytes: phase.phase_handshake_ke_online_uploaded_bytes,
            phase_handshake_ke_online_downloaded_bytes: phase.phase_handshake_ke_online_downloaded_bytes,
            phase_handshake_ke_online_io_wait_read_ms: phase.phase_handshake_ke_online_io_wait_read_ms,
            phase_handshake_ke_online_io_wait_write_ms: phase.phase_handshake_ke_online_io_wait_write_ms,
            phase_handshake_prf_session_keys_count: phase.phase_handshake_prf_session_keys_count,
            phase_handshake_prf_session_keys_time_ms: phase.phase_handshake_prf_session_keys_time_ms,
            phase_handshake_prf_session_keys_uploaded_bytes: phase.phase_handshake_prf_session_keys_uploaded_bytes,
            phase_handshake_prf_session_keys_downloaded_bytes: phase.phase_handshake_prf_session_keys_downloaded_bytes,
            phase_handshake_prf_session_keys_io_wait_read_ms: phase.phase_handshake_prf_session_keys_io_wait_read_ms,
            phase_handshake_prf_session_keys_io_wait_write_ms: phase.phase_handshake_prf_session_keys_io_wait_write_ms,
            phase_handshake_record_setup_count: phase.phase_handshake_record_setup_count,
            phase_handshake_record_setup_time_ms: phase.phase_handshake_record_setup_time_ms,
            phase_handshake_record_setup_uploaded_bytes: phase.phase_handshake_record_setup_uploaded_bytes,
            phase_handshake_record_setup_downloaded_bytes: phase.phase_handshake_record_setup_downloaded_bytes,
            phase_handshake_record_setup_io_wait_read_ms: phase.phase_handshake_record_setup_io_wait_read_ms,
            phase_handshake_record_setup_io_wait_write_ms: phase.phase_handshake_record_setup_io_wait_write_ms,
            phase_handshake_prf_server_finished_count: phase.phase_handshake_prf_server_finished_count,
            phase_handshake_prf_server_finished_time_ms: phase.phase_handshake_prf_server_finished_time_ms,
            phase_handshake_prf_server_finished_uploaded_bytes: phase.phase_handshake_prf_server_finished_uploaded_bytes,
            phase_handshake_prf_server_finished_downloaded_bytes: phase.phase_handshake_prf_server_finished_downloaded_bytes,
            phase_handshake_prf_server_finished_io_wait_read_ms: phase.phase_handshake_prf_server_finished_io_wait_read_ms,
            phase_handshake_prf_server_finished_io_wait_write_ms: phase.phase_handshake_prf_server_finished_io_wait_write_ms,
            phase_handshake_prf_client_finished_count: phase.phase_handshake_prf_client_finished_count,
            phase_handshake_prf_client_finished_time_ms: phase.phase_handshake_prf_client_finished_time_ms,
            phase_handshake_prf_client_finished_uploaded_bytes: phase.phase_handshake_prf_client_finished_uploaded_bytes,
            phase_handshake_prf_client_finished_downloaded_bytes: phase.phase_handshake_prf_client_finished_downloaded_bytes,
            phase_handshake_prf_client_finished_io_wait_read_ms: phase.phase_handshake_prf_client_finished_io_wait_read_ms,
            phase_handshake_prf_client_finished_io_wait_write_ms: phase.phase_handshake_prf_client_finished_io_wait_write_ms,
            phase_record_layer_flush_count: phase.phase_record_layer_flush_count,
            phase_record_layer_flush_time_ms: phase.phase_record_layer_flush_time_ms,
            phase_record_layer_flush_uploaded_bytes: phase.phase_record_layer_flush_uploaded_bytes,
            phase_record_layer_flush_downloaded_bytes: phase.phase_record_layer_flush_downloaded_bytes,
            phase_record_layer_flush_io_wait_read_ms: phase.phase_record_layer_flush_io_wait_read_ms,
            phase_record_layer_flush_io_wait_write_ms: phase.phase_record_layer_flush_io_wait_write_ms,
            phase_finalize_tls_auth_count: phase.phase_finalize_tls_auth_count,
            phase_finalize_tls_auth_time_ms: phase.phase_finalize_tls_auth_time_ms,
            phase_finalize_tls_auth_uploaded_bytes: phase.phase_finalize_tls_auth_uploaded_bytes,
            phase_finalize_tls_auth_downloaded_bytes: phase.phase_finalize_tls_auth_downloaded_bytes,
            phase_finalize_tls_auth_io_wait_read_ms: phase.phase_finalize_tls_auth_io_wait_read_ms,
            phase_finalize_tls_auth_io_wait_write_ms: phase.phase_finalize_tls_auth_io_wait_write_ms,
            phase_prove_transcript_count: phase.phase_prove_transcript_count,
            phase_prove_transcript_time_ms: phase.phase_prove_transcript_time_ms,
            phase_prove_transcript_uploaded_bytes: phase.phase_prove_transcript_uploaded_bytes,
            phase_prove_transcript_downloaded_bytes: phase.phase_prove_transcript_downloaded_bytes,
            phase_prove_transcript_io_wait_read_ms: phase.phase_prove_transcript_io_wait_read_ms,
            phase_prove_transcript_io_wait_write_ms: phase.phase_prove_transcript_io_wait_write_ms,
        }
    }
}

impl From<ProverMetricsRecord> for ProverMetrics {
    fn from(value: ProverMetricsRecord) -> Self {
        Self {
            time_preprocess: value.time_preprocess,
            time_online: value.time_online,
            time_total: value.time_total,
            uploaded_preprocess: value.uploaded_preprocess,
            downloaded_preprocess: value.downloaded_preprocess,
            uploaded_online: value.uploaded_online,
            downloaded_online: value.downloaded_online,
            uploaded_total: value.uploaded_total,
            downloaded_total: value.downloaded_total,
            heap_max_bytes: value.heap_max_bytes,
            phase_metrics: PhaseMetrics {
                phase_preprocess_setup_count: value.phase_preprocess_setup_count,
                phase_preprocess_setup_time_ms: value.phase_preprocess_setup_time_ms,
                phase_preprocess_setup_uploaded_bytes: value.phase_preprocess_setup_uploaded_bytes,
                phase_preprocess_setup_downloaded_bytes: value.phase_preprocess_setup_downloaded_bytes,
                phase_preprocess_setup_io_wait_read_ms: value.phase_preprocess_setup_io_wait_read_ms,
                phase_preprocess_setup_io_wait_write_ms: value.phase_preprocess_setup_io_wait_write_ms,
                phase_handshake_ke_online_count: value.phase_handshake_ke_online_count,
                phase_handshake_ke_online_time_ms: value.phase_handshake_ke_online_time_ms,
                phase_handshake_ke_online_uploaded_bytes: value.phase_handshake_ke_online_uploaded_bytes,
                phase_handshake_ke_online_downloaded_bytes: value.phase_handshake_ke_online_downloaded_bytes,
                phase_handshake_ke_online_io_wait_read_ms: value.phase_handshake_ke_online_io_wait_read_ms,
                phase_handshake_ke_online_io_wait_write_ms: value.phase_handshake_ke_online_io_wait_write_ms,
                phase_handshake_prf_session_keys_count: value.phase_handshake_prf_session_keys_count,
                phase_handshake_prf_session_keys_time_ms: value.phase_handshake_prf_session_keys_time_ms,
                phase_handshake_prf_session_keys_uploaded_bytes: value.phase_handshake_prf_session_keys_uploaded_bytes,
                phase_handshake_prf_session_keys_downloaded_bytes: value.phase_handshake_prf_session_keys_downloaded_bytes,
                phase_handshake_prf_session_keys_io_wait_read_ms: value.phase_handshake_prf_session_keys_io_wait_read_ms,
                phase_handshake_prf_session_keys_io_wait_write_ms: value.phase_handshake_prf_session_keys_io_wait_write_ms,
                phase_handshake_record_setup_count: value.phase_handshake_record_setup_count,
                phase_handshake_record_setup_time_ms: value.phase_handshake_record_setup_time_ms,
                phase_handshake_record_setup_uploaded_bytes: value.phase_handshake_record_setup_uploaded_bytes,
                phase_handshake_record_setup_downloaded_bytes: value.phase_handshake_record_setup_downloaded_bytes,
                phase_handshake_record_setup_io_wait_read_ms: value.phase_handshake_record_setup_io_wait_read_ms,
                phase_handshake_record_setup_io_wait_write_ms: value.phase_handshake_record_setup_io_wait_write_ms,
                phase_handshake_prf_server_finished_count: value.phase_handshake_prf_server_finished_count,
                phase_handshake_prf_server_finished_time_ms: value.phase_handshake_prf_server_finished_time_ms,
                phase_handshake_prf_server_finished_uploaded_bytes: value.phase_handshake_prf_server_finished_uploaded_bytes,
                phase_handshake_prf_server_finished_downloaded_bytes: value.phase_handshake_prf_server_finished_downloaded_bytes,
                phase_handshake_prf_server_finished_io_wait_read_ms: value.phase_handshake_prf_server_finished_io_wait_read_ms,
                phase_handshake_prf_server_finished_io_wait_write_ms: value.phase_handshake_prf_server_finished_io_wait_write_ms,
                phase_handshake_prf_client_finished_count: value.phase_handshake_prf_client_finished_count,
                phase_handshake_prf_client_finished_time_ms: value.phase_handshake_prf_client_finished_time_ms,
                phase_handshake_prf_client_finished_uploaded_bytes: value.phase_handshake_prf_client_finished_uploaded_bytes,
                phase_handshake_prf_client_finished_downloaded_bytes: value.phase_handshake_prf_client_finished_downloaded_bytes,
                phase_handshake_prf_client_finished_io_wait_read_ms: value.phase_handshake_prf_client_finished_io_wait_read_ms,
                phase_handshake_prf_client_finished_io_wait_write_ms: value.phase_handshake_prf_client_finished_io_wait_write_ms,
                phase_record_layer_flush_count: value.phase_record_layer_flush_count,
                phase_record_layer_flush_time_ms: value.phase_record_layer_flush_time_ms,
                phase_record_layer_flush_uploaded_bytes: value.phase_record_layer_flush_uploaded_bytes,
                phase_record_layer_flush_downloaded_bytes: value.phase_record_layer_flush_downloaded_bytes,
                phase_record_layer_flush_io_wait_read_ms: value.phase_record_layer_flush_io_wait_read_ms,
                phase_record_layer_flush_io_wait_write_ms: value.phase_record_layer_flush_io_wait_write_ms,
                phase_finalize_tls_auth_count: value.phase_finalize_tls_auth_count,
                phase_finalize_tls_auth_time_ms: value.phase_finalize_tls_auth_time_ms,
                phase_finalize_tls_auth_uploaded_bytes: value.phase_finalize_tls_auth_uploaded_bytes,
                phase_finalize_tls_auth_downloaded_bytes: value.phase_finalize_tls_auth_downloaded_bytes,
                phase_finalize_tls_auth_io_wait_read_ms: value.phase_finalize_tls_auth_io_wait_read_ms,
                phase_finalize_tls_auth_io_wait_write_ms: value.phase_finalize_tls_auth_io_wait_write_ms,
                phase_prove_transcript_count: value.phase_prove_transcript_count,
                phase_prove_transcript_time_ms: value.phase_prove_transcript_time_ms,
                phase_prove_transcript_uploaded_bytes: value.phase_prove_transcript_uploaded_bytes,
                phase_prove_transcript_downloaded_bytes: value.phase_prove_transcript_downloaded_bytes,
                phase_prove_transcript_io_wait_read_ms: value.phase_prove_transcript_io_wait_read_ms,
                phase_prove_transcript_io_wait_write_ms: value.phase_prove_transcript_io_wait_write_ms,
            },
        }
    }
}

impl Serialize for ProverMetrics {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ProverMetricsRecord::from(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProverMetrics {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ProverMetricsRecord::deserialize(deserializer).map(Into::into)
    }
}

#[derive(Debug, Clone)]
pub struct Measurement {
    pub group: Option<String>,
    pub name: Option<String>,
    pub latency: usize,
    pub bandwidth: usize,
    pub upload_size: usize,
    pub download_size: usize,
    pub defer_decryption: bool,
    /// Time taken to preprocess the connection in milliseconds.
    pub time_preprocess: u64,
    /// TLS connection online time in milliseconds.
    pub time_online: u64,
    /// Total runtime of the benchmark in milliseconds.
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
    pub phase_metrics: PhaseMetrics,
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
            phase_metrics: metrics.phase_metrics,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeasurementRecord {
    group: Option<String>,
    name: Option<String>,
    latency: usize,
    bandwidth: usize,
    upload_size: usize,
    download_size: usize,
    defer_decryption: bool,
    time_preprocess: u64,
    time_online: u64,
    time_total: u64,
    uploaded_preprocess: u64,
    downloaded_preprocess: u64,
    uploaded_online: u64,
    downloaded_online: u64,
    uploaded_total: u64,
    downloaded_total: u64,
    heap_max_bytes: Option<usize>,
    #[serde(default)]
    phase_preprocess_setup_count: u64,
    #[serde(default)]
    phase_preprocess_setup_time_ms: u64,
    #[serde(default)]
    phase_preprocess_setup_uploaded_bytes: u64,
    #[serde(default)]
    phase_preprocess_setup_downloaded_bytes: u64,
    #[serde(default)]
    phase_preprocess_setup_io_wait_read_ms: u64,
    #[serde(default)]
    phase_preprocess_setup_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_ke_online_count: u64,
    #[serde(default)]
    phase_handshake_ke_online_time_ms: u64,
    #[serde(default)]
    phase_handshake_ke_online_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_ke_online_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_ke_online_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_ke_online_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_count: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_time_ms: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_prf_session_keys_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_record_setup_count: u64,
    #[serde(default)]
    phase_handshake_record_setup_time_ms: u64,
    #[serde(default)]
    phase_handshake_record_setup_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_record_setup_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_record_setup_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_record_setup_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_count: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_time_ms: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_prf_server_finished_io_wait_write_ms: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_count: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_time_ms: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_uploaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_downloaded_bytes: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_io_wait_read_ms: u64,
    #[serde(default)]
    phase_handshake_prf_client_finished_io_wait_write_ms: u64,
    #[serde(default)]
    phase_record_layer_flush_count: u64,
    #[serde(default)]
    phase_record_layer_flush_time_ms: u64,
    #[serde(default)]
    phase_record_layer_flush_uploaded_bytes: u64,
    #[serde(default)]
    phase_record_layer_flush_downloaded_bytes: u64,
    #[serde(default)]
    phase_record_layer_flush_io_wait_read_ms: u64,
    #[serde(default)]
    phase_record_layer_flush_io_wait_write_ms: u64,
    #[serde(default)]
    phase_finalize_tls_auth_count: u64,
    #[serde(default)]
    phase_finalize_tls_auth_time_ms: u64,
    #[serde(default)]
    phase_finalize_tls_auth_uploaded_bytes: u64,
    #[serde(default)]
    phase_finalize_tls_auth_downloaded_bytes: u64,
    #[serde(default)]
    phase_finalize_tls_auth_io_wait_read_ms: u64,
    #[serde(default)]
    phase_finalize_tls_auth_io_wait_write_ms: u64,
    #[serde(default)]
    phase_prove_transcript_count: u64,
    #[serde(default)]
    phase_prove_transcript_time_ms: u64,
    #[serde(default)]
    phase_prove_transcript_uploaded_bytes: u64,
    #[serde(default)]
    phase_prove_transcript_downloaded_bytes: u64,
    #[serde(default)]
    phase_prove_transcript_io_wait_read_ms: u64,
    #[serde(default)]
    phase_prove_transcript_io_wait_write_ms: u64,
}

impl From<Measurement> for MeasurementRecord {
    fn from(value: Measurement) -> Self {
        let phase = value.phase_metrics;
        Self {
            group: value.group,
            name: value.name,
            latency: value.latency,
            bandwidth: value.bandwidth,
            upload_size: value.upload_size,
            download_size: value.download_size,
            defer_decryption: value.defer_decryption,
            time_preprocess: value.time_preprocess,
            time_online: value.time_online,
            time_total: value.time_total,
            uploaded_preprocess: value.uploaded_preprocess,
            downloaded_preprocess: value.downloaded_preprocess,
            uploaded_online: value.uploaded_online,
            downloaded_online: value.downloaded_online,
            uploaded_total: value.uploaded_total,
            downloaded_total: value.downloaded_total,
            heap_max_bytes: value.heap_max_bytes,
            phase_preprocess_setup_count: phase.phase_preprocess_setup_count,
            phase_preprocess_setup_time_ms: phase.phase_preprocess_setup_time_ms,
            phase_preprocess_setup_uploaded_bytes: phase.phase_preprocess_setup_uploaded_bytes,
            phase_preprocess_setup_downloaded_bytes: phase.phase_preprocess_setup_downloaded_bytes,
            phase_preprocess_setup_io_wait_read_ms: phase.phase_preprocess_setup_io_wait_read_ms,
            phase_preprocess_setup_io_wait_write_ms: phase.phase_preprocess_setup_io_wait_write_ms,
            phase_handshake_ke_online_count: phase.phase_handshake_ke_online_count,
            phase_handshake_ke_online_time_ms: phase.phase_handshake_ke_online_time_ms,
            phase_handshake_ke_online_uploaded_bytes: phase.phase_handshake_ke_online_uploaded_bytes,
            phase_handshake_ke_online_downloaded_bytes: phase.phase_handshake_ke_online_downloaded_bytes,
            phase_handshake_ke_online_io_wait_read_ms: phase.phase_handshake_ke_online_io_wait_read_ms,
            phase_handshake_ke_online_io_wait_write_ms: phase.phase_handshake_ke_online_io_wait_write_ms,
            phase_handshake_prf_session_keys_count: phase.phase_handshake_prf_session_keys_count,
            phase_handshake_prf_session_keys_time_ms: phase.phase_handshake_prf_session_keys_time_ms,
            phase_handshake_prf_session_keys_uploaded_bytes: phase.phase_handshake_prf_session_keys_uploaded_bytes,
            phase_handshake_prf_session_keys_downloaded_bytes: phase.phase_handshake_prf_session_keys_downloaded_bytes,
            phase_handshake_prf_session_keys_io_wait_read_ms: phase.phase_handshake_prf_session_keys_io_wait_read_ms,
            phase_handshake_prf_session_keys_io_wait_write_ms: phase.phase_handshake_prf_session_keys_io_wait_write_ms,
            phase_handshake_record_setup_count: phase.phase_handshake_record_setup_count,
            phase_handshake_record_setup_time_ms: phase.phase_handshake_record_setup_time_ms,
            phase_handshake_record_setup_uploaded_bytes: phase.phase_handshake_record_setup_uploaded_bytes,
            phase_handshake_record_setup_downloaded_bytes: phase.phase_handshake_record_setup_downloaded_bytes,
            phase_handshake_record_setup_io_wait_read_ms: phase.phase_handshake_record_setup_io_wait_read_ms,
            phase_handshake_record_setup_io_wait_write_ms: phase.phase_handshake_record_setup_io_wait_write_ms,
            phase_handshake_prf_server_finished_count: phase.phase_handshake_prf_server_finished_count,
            phase_handshake_prf_server_finished_time_ms: phase.phase_handshake_prf_server_finished_time_ms,
            phase_handshake_prf_server_finished_uploaded_bytes: phase.phase_handshake_prf_server_finished_uploaded_bytes,
            phase_handshake_prf_server_finished_downloaded_bytes: phase.phase_handshake_prf_server_finished_downloaded_bytes,
            phase_handshake_prf_server_finished_io_wait_read_ms: phase.phase_handshake_prf_server_finished_io_wait_read_ms,
            phase_handshake_prf_server_finished_io_wait_write_ms: phase.phase_handshake_prf_server_finished_io_wait_write_ms,
            phase_handshake_prf_client_finished_count: phase.phase_handshake_prf_client_finished_count,
            phase_handshake_prf_client_finished_time_ms: phase.phase_handshake_prf_client_finished_time_ms,
            phase_handshake_prf_client_finished_uploaded_bytes: phase.phase_handshake_prf_client_finished_uploaded_bytes,
            phase_handshake_prf_client_finished_downloaded_bytes: phase.phase_handshake_prf_client_finished_downloaded_bytes,
            phase_handshake_prf_client_finished_io_wait_read_ms: phase.phase_handshake_prf_client_finished_io_wait_read_ms,
            phase_handshake_prf_client_finished_io_wait_write_ms: phase.phase_handshake_prf_client_finished_io_wait_write_ms,
            phase_record_layer_flush_count: phase.phase_record_layer_flush_count,
            phase_record_layer_flush_time_ms: phase.phase_record_layer_flush_time_ms,
            phase_record_layer_flush_uploaded_bytes: phase.phase_record_layer_flush_uploaded_bytes,
            phase_record_layer_flush_downloaded_bytes: phase.phase_record_layer_flush_downloaded_bytes,
            phase_record_layer_flush_io_wait_read_ms: phase.phase_record_layer_flush_io_wait_read_ms,
            phase_record_layer_flush_io_wait_write_ms: phase.phase_record_layer_flush_io_wait_write_ms,
            phase_finalize_tls_auth_count: phase.phase_finalize_tls_auth_count,
            phase_finalize_tls_auth_time_ms: phase.phase_finalize_tls_auth_time_ms,
            phase_finalize_tls_auth_uploaded_bytes: phase.phase_finalize_tls_auth_uploaded_bytes,
            phase_finalize_tls_auth_downloaded_bytes: phase.phase_finalize_tls_auth_downloaded_bytes,
            phase_finalize_tls_auth_io_wait_read_ms: phase.phase_finalize_tls_auth_io_wait_read_ms,
            phase_finalize_tls_auth_io_wait_write_ms: phase.phase_finalize_tls_auth_io_wait_write_ms,
            phase_prove_transcript_count: phase.phase_prove_transcript_count,
            phase_prove_transcript_time_ms: phase.phase_prove_transcript_time_ms,
            phase_prove_transcript_uploaded_bytes: phase.phase_prove_transcript_uploaded_bytes,
            phase_prove_transcript_downloaded_bytes: phase.phase_prove_transcript_downloaded_bytes,
            phase_prove_transcript_io_wait_read_ms: phase.phase_prove_transcript_io_wait_read_ms,
            phase_prove_transcript_io_wait_write_ms: phase.phase_prove_transcript_io_wait_write_ms,
        }
    }
}

impl From<MeasurementRecord> for Measurement {
    fn from(value: MeasurementRecord) -> Self {
        Self {
            group: value.group,
            name: value.name,
            latency: value.latency,
            bandwidth: value.bandwidth,
            upload_size: value.upload_size,
            download_size: value.download_size,
            defer_decryption: value.defer_decryption,
            time_preprocess: value.time_preprocess,
            time_online: value.time_online,
            time_total: value.time_total,
            uploaded_preprocess: value.uploaded_preprocess,
            downloaded_preprocess: value.downloaded_preprocess,
            uploaded_online: value.uploaded_online,
            downloaded_online: value.downloaded_online,
            uploaded_total: value.uploaded_total,
            downloaded_total: value.downloaded_total,
            heap_max_bytes: value.heap_max_bytes,
            phase_metrics: PhaseMetrics {
                phase_preprocess_setup_count: value.phase_preprocess_setup_count,
                phase_preprocess_setup_time_ms: value.phase_preprocess_setup_time_ms,
                phase_preprocess_setup_uploaded_bytes: value.phase_preprocess_setup_uploaded_bytes,
                phase_preprocess_setup_downloaded_bytes: value.phase_preprocess_setup_downloaded_bytes,
                phase_preprocess_setup_io_wait_read_ms: value.phase_preprocess_setup_io_wait_read_ms,
                phase_preprocess_setup_io_wait_write_ms: value.phase_preprocess_setup_io_wait_write_ms,
                phase_handshake_ke_online_count: value.phase_handshake_ke_online_count,
                phase_handshake_ke_online_time_ms: value.phase_handshake_ke_online_time_ms,
                phase_handshake_ke_online_uploaded_bytes: value.phase_handshake_ke_online_uploaded_bytes,
                phase_handshake_ke_online_downloaded_bytes: value.phase_handshake_ke_online_downloaded_bytes,
                phase_handshake_ke_online_io_wait_read_ms: value.phase_handshake_ke_online_io_wait_read_ms,
                phase_handshake_ke_online_io_wait_write_ms: value.phase_handshake_ke_online_io_wait_write_ms,
                phase_handshake_prf_session_keys_count: value.phase_handshake_prf_session_keys_count,
                phase_handshake_prf_session_keys_time_ms: value.phase_handshake_prf_session_keys_time_ms,
                phase_handshake_prf_session_keys_uploaded_bytes: value.phase_handshake_prf_session_keys_uploaded_bytes,
                phase_handshake_prf_session_keys_downloaded_bytes: value.phase_handshake_prf_session_keys_downloaded_bytes,
                phase_handshake_prf_session_keys_io_wait_read_ms: value.phase_handshake_prf_session_keys_io_wait_read_ms,
                phase_handshake_prf_session_keys_io_wait_write_ms: value.phase_handshake_prf_session_keys_io_wait_write_ms,
                phase_handshake_record_setup_count: value.phase_handshake_record_setup_count,
                phase_handshake_record_setup_time_ms: value.phase_handshake_record_setup_time_ms,
                phase_handshake_record_setup_uploaded_bytes: value.phase_handshake_record_setup_uploaded_bytes,
                phase_handshake_record_setup_downloaded_bytes: value.phase_handshake_record_setup_downloaded_bytes,
                phase_handshake_record_setup_io_wait_read_ms: value.phase_handshake_record_setup_io_wait_read_ms,
                phase_handshake_record_setup_io_wait_write_ms: value.phase_handshake_record_setup_io_wait_write_ms,
                phase_handshake_prf_server_finished_count: value.phase_handshake_prf_server_finished_count,
                phase_handshake_prf_server_finished_time_ms: value.phase_handshake_prf_server_finished_time_ms,
                phase_handshake_prf_server_finished_uploaded_bytes: value.phase_handshake_prf_server_finished_uploaded_bytes,
                phase_handshake_prf_server_finished_downloaded_bytes: value.phase_handshake_prf_server_finished_downloaded_bytes,
                phase_handshake_prf_server_finished_io_wait_read_ms: value.phase_handshake_prf_server_finished_io_wait_read_ms,
                phase_handshake_prf_server_finished_io_wait_write_ms: value.phase_handshake_prf_server_finished_io_wait_write_ms,
                phase_handshake_prf_client_finished_count: value.phase_handshake_prf_client_finished_count,
                phase_handshake_prf_client_finished_time_ms: value.phase_handshake_prf_client_finished_time_ms,
                phase_handshake_prf_client_finished_uploaded_bytes: value.phase_handshake_prf_client_finished_uploaded_bytes,
                phase_handshake_prf_client_finished_downloaded_bytes: value.phase_handshake_prf_client_finished_downloaded_bytes,
                phase_handshake_prf_client_finished_io_wait_read_ms: value.phase_handshake_prf_client_finished_io_wait_read_ms,
                phase_handshake_prf_client_finished_io_wait_write_ms: value.phase_handshake_prf_client_finished_io_wait_write_ms,
                phase_record_layer_flush_count: value.phase_record_layer_flush_count,
                phase_record_layer_flush_time_ms: value.phase_record_layer_flush_time_ms,
                phase_record_layer_flush_uploaded_bytes: value.phase_record_layer_flush_uploaded_bytes,
                phase_record_layer_flush_downloaded_bytes: value.phase_record_layer_flush_downloaded_bytes,
                phase_record_layer_flush_io_wait_read_ms: value.phase_record_layer_flush_io_wait_read_ms,
                phase_record_layer_flush_io_wait_write_ms: value.phase_record_layer_flush_io_wait_write_ms,
                phase_finalize_tls_auth_count: value.phase_finalize_tls_auth_count,
                phase_finalize_tls_auth_time_ms: value.phase_finalize_tls_auth_time_ms,
                phase_finalize_tls_auth_uploaded_bytes: value.phase_finalize_tls_auth_uploaded_bytes,
                phase_finalize_tls_auth_downloaded_bytes: value.phase_finalize_tls_auth_downloaded_bytes,
                phase_finalize_tls_auth_io_wait_read_ms: value.phase_finalize_tls_auth_io_wait_read_ms,
                phase_finalize_tls_auth_io_wait_write_ms: value.phase_finalize_tls_auth_io_wait_write_ms,
                phase_prove_transcript_count: value.phase_prove_transcript_count,
                phase_prove_transcript_time_ms: value.phase_prove_transcript_time_ms,
                phase_prove_transcript_uploaded_bytes: value.phase_prove_transcript_uploaded_bytes,
                phase_prove_transcript_downloaded_bytes: value.phase_prove_transcript_downloaded_bytes,
                phase_prove_transcript_io_wait_read_ms: value.phase_prove_transcript_io_wait_read_ms,
                phase_prove_transcript_io_wait_write_ms: value.phase_prove_transcript_io_wait_write_ms,
            },
        }
    }
}

impl Serialize for Measurement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        MeasurementRecord::from(self.clone()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Measurement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        MeasurementRecord::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bincode;
    use csv::{ReaderBuilder, WriterBuilder};
    use serde_json::json;

    use super::{Bench, BenchOutput, Measurement, PhaseMetrics, ProverMetrics};

    #[test]
    fn prover_metrics_round_trip_with_phase_metrics() {
        let metrics = ProverMetrics {
            time_preprocess: 1,
            time_online: 2,
            time_total: 3,
            uploaded_preprocess: 4,
            downloaded_preprocess: 5,
            uploaded_online: 6,
            downloaded_online: 7,
            uploaded_total: 8,
            downloaded_total: 9,
            heap_max_bytes: Some(10),
            phase_metrics: PhaseMetrics {
                phase_record_layer_flush_count: 2,
                phase_record_layer_flush_time_ms: 11,
                phase_record_layer_flush_uploaded_bytes: 12,
                phase_record_layer_flush_downloaded_bytes: 13,
                phase_record_layer_flush_io_wait_read_ms: 14,
                phase_record_layer_flush_io_wait_write_ms: 15,
                ..PhaseMetrics::default()
            },
        };

        let encoded = serde_json::to_string(&metrics).expect("metrics should serialize");
        let decoded: ProverMetrics =
            serde_json::from_str(&encoded).expect("metrics should deserialize");

        assert_eq!(decoded.phase_metrics.phase_record_layer_flush_count, 2);
        assert_eq!(decoded.phase_metrics.phase_record_layer_flush_time_ms, 11);
        assert_eq!(decoded.phase_metrics.phase_record_layer_flush_uploaded_bytes, 12);
        assert_eq!(decoded.phase_metrics.phase_record_layer_flush_downloaded_bytes, 13);
        assert_eq!(decoded.phase_metrics.phase_record_layer_flush_io_wait_read_ms, 14);
        assert_eq!(decoded.phase_metrics.phase_record_layer_flush_io_wait_write_ms, 15);
    }

    #[test]
    fn bench_output_bincode_round_trip_with_phase_metrics() {
        let output = BenchOutput::Prover {
            metrics: ProverMetrics {
                time_preprocess: 1,
                time_online: 2,
                time_total: 3,
                uploaded_preprocess: 4,
                downloaded_preprocess: 5,
                uploaded_online: 6,
                downloaded_online: 7,
                uploaded_total: 8,
                downloaded_total: 9,
                heap_max_bytes: Some(10),
                phase_metrics: PhaseMetrics {
                    phase_record_layer_flush_count: 2,
                    phase_record_layer_flush_time_ms: 11,
                    phase_record_layer_flush_uploaded_bytes: 12,
                    phase_record_layer_flush_downloaded_bytes: 13,
                    phase_record_layer_flush_io_wait_read_ms: 14,
                    phase_record_layer_flush_io_wait_write_ms: 15,
                    ..PhaseMetrics::default()
                },
            },
        };

        let encoded = bincode::serialize(&output).expect("bench output should bincode serialize");
        let decoded: BenchOutput =
            bincode::deserialize(&encoded).expect("bench output should bincode deserialize");

        let BenchOutput::Prover { metrics } = decoded else {
            panic!("expected prover bench output");
        };

        assert_eq!(metrics.phase_metrics.phase_record_layer_flush_count, 2);
        assert_eq!(metrics.phase_metrics.phase_record_layer_flush_time_ms, 11);
        assert_eq!(metrics.phase_metrics.phase_record_layer_flush_uploaded_bytes, 12);
        assert_eq!(metrics.phase_metrics.phase_record_layer_flush_downloaded_bytes, 13);
        assert_eq!(metrics.phase_metrics.phase_record_layer_flush_io_wait_read_ms, 14);
        assert_eq!(metrics.phase_metrics.phase_record_layer_flush_io_wait_write_ms, 15);
    }

    #[test]
    fn measurement_deserializes_old_rows_without_phase_columns() {
        let old_row = json!({
            "group": "group-a",
            "name": "bench-a",
            "latency": 10,
            "bandwidth": 1000,
            "upload_size": 1024,
            "download_size": 2048,
            "defer_decryption": true,
            "time_preprocess": 1,
            "time_online": 2,
            "time_total": 3,
            "uploaded_preprocess": 4,
            "downloaded_preprocess": 5,
            "uploaded_online": 6,
            "downloaded_online": 7,
            "uploaded_total": 8,
            "downloaded_total": 9,
            "heap_max_bytes": null
        });

        let measurement: Measurement =
            serde_json::from_value(old_row).expect("old measurement should deserialize");

        assert_eq!(measurement.phase_metrics.phase_preprocess_setup_count, 0);
        assert_eq!(measurement.phase_metrics.phase_record_layer_flush_count, 0);
        assert_eq!(measurement.phase_metrics.phase_prove_transcript_count, 0);
    }

    #[test]
    fn measurement_csv_round_trip_preserves_phase_columns() {
        let measurement = Measurement::new(
            Bench {
                group: Some("group-a".into()),
                name: Some("bench-a".into()),
                protocol_latency: 10,
                app_latency: 10,
                bandwidth: 1000,
                upload_size: 1024,
                download_size: 2048,
                defer_decryption: true,
                memory_profile: false,
                reveal_all: false,
            },
            ProverMetrics {
                time_preprocess: 1,
                time_online: 2,
                time_total: 3,
                uploaded_preprocess: 4,
                downloaded_preprocess: 5,
                uploaded_online: 6,
                downloaded_online: 7,
                uploaded_total: 8,
                downloaded_total: 9,
                heap_max_bytes: None,
                phase_metrics: PhaseMetrics {
                    phase_prove_transcript_count: 1,
                    phase_prove_transcript_time_ms: 11,
                    phase_prove_transcript_uploaded_bytes: 12,
                    phase_prove_transcript_downloaded_bytes: 13,
                    phase_prove_transcript_io_wait_read_ms: 14,
                    phase_prove_transcript_io_wait_write_ms: 15,
                    ..PhaseMetrics::default()
                },
            },
        );

        let mut writer = WriterBuilder::new().from_writer(Vec::new());
        writer
            .serialize(&measurement)
            .expect("measurement should serialize to csv");
        let csv = String::from_utf8(
            writer
                .into_inner()
                .expect("writer should yield bytes"),
        )
        .expect("csv should be utf8");

        let mut reader = ReaderBuilder::new().from_reader(Cursor::new(csv));
        let decoded: Vec<Measurement> = reader
            .deserialize()
            .collect::<Result<_, _>>()
            .expect("csv should deserialize");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].phase_metrics.phase_prove_transcript_count, 1);
        assert_eq!(decoded[0].phase_metrics.phase_prove_transcript_time_ms, 11);
    }

    #[test]
    fn measurement_csv_deserializes_old_rows_without_phase_columns() {
        let csv = "\
group,name,latency,bandwidth,upload_size,download_size,defer_decryption,time_preprocess,time_online,time_total,uploaded_preprocess,downloaded_preprocess,uploaded_online,downloaded_online,uploaded_total,downloaded_total,heap_max_bytes\n\
group-a,bench-a,10,1000,1024,2048,true,1,2,3,4,5,6,7,8,9,\n";

        let mut reader = ReaderBuilder::new().from_reader(Cursor::new(csv));
        let decoded: Vec<Measurement> = reader
            .deserialize()
            .collect::<Result<_, _>>()
            .expect("old csv rows should deserialize");

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].phase_metrics.phase_preprocess_setup_count, 0);
        assert_eq!(decoded[0].phase_metrics.phase_record_layer_flush_count, 0);
    }
}
