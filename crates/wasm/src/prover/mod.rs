//! WASM Prover bindings.

mod config;

pub use config::ProverConfig;

use tlsn_sdk_core::{
    NetworkSetting as CoreNetworkSetting, ProverConfig as CoreProverConfig, ProverMode, SdkProver,
};
use wasm_bindgen::{JsError, prelude::*};

use crate::{
    io::{JsIo, JsIoAdapter},
    types::*,
};

type Result<T> = std::result::Result<T, JsError>;

/// Prover for the TLSNotary protocol.
///
/// The prover connects to both a verifier and a target server, executing the
/// MPC-TLS protocol to generate verifiable proofs of the TLS session.
#[wasm_bindgen(js_name = Prover)]
pub struct JsProver {
    inner: SdkProver,
    progress_callback: Option<js_sys::Function>,
}

#[wasm_bindgen(js_class = Prover)]
impl JsProver {
    /// Creates a new Prover with the given configuration.
    #[wasm_bindgen(constructor)]
    pub fn new(config: ProverConfig) -> Result<JsProver> {
        let core_config = convert_prover_config(config)?;
        let inner = SdkProver::new(core_config).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(JsProver {
            inner,
            progress_callback: None,
        })
    }

    /// Sets a progress callback that receives structured progress updates.
    ///
    /// The callback receives a single argument: `{ step: string, progress:
    /// number, message: string }`.
    ///
    /// Steps emitted: `MPC_SETUP`, `CONNECTING_TO_SERVER`, `SENDING_REQUEST`,
    /// `REQUEST_COMPLETE`, `REVEAL`, `FINALIZED`.
    pub fn set_progress_callback(&mut self, callback: js_sys::Function) {
        self.progress_callback = Some(callback);
    }

    /// Sets up the prover with the verifier.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    ///
    /// # Arguments
    ///
    /// * `verifier_io` - A JavaScript object implementing the IoChannel
    ///   interface, connected to the verifier.
    pub async fn setup(&mut self, verifier_io: JsIo) -> Result<()> {
        self.emit_progress("MPC_SETUP", 0.1, "Connecting to verifier...");

        let adapter = JsIoAdapter::new(verifier_io);
        self.inner
            .setup(adapter)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        self.emit_progress("MPC_SETUP", 0.2, "MPC setup complete");

        Ok(())
    }

    /// Sends an HTTP request to the server.
    ///
    /// # Arguments
    ///
    /// * `server_io` - An IoChannel connected to the server. Must be provided
    ///   in MPC mode. Must be `None` in proxy mode, where the connection is
    ///   routed through the verifier.
    /// * `request` - The HTTP request to send.
    pub async fn send_request(
        &mut self,
        server_io: Option<JsIo>,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        self.emit_progress(
            "CONNECTING_TO_SERVER",
            0.3,
            "Connecting to application server...",
        );

        let core_request = convert_http_request(request);

        self.emit_progress("SENDING_REQUEST", 0.4, "Sending request...");

        let core_response = match (self.inner.mode(), server_io) {
            (ProverMode::Mpc, Some(server_io)) => {
                self.inner
                    .send_request_mpc(JsIoAdapter::new(server_io), core_request)
                    .await
            }
            (ProverMode::Mpc, None) => {
                return Err(JsError::new("server_io is required in MPC mode"));
            }
            (ProverMode::Proxy, None) => self.inner.send_request_proxy(core_request).await,
            (ProverMode::Proxy, Some(_)) => {
                return Err(JsError::new("server_io must not be provided in proxy mode"));
            }
        }
        .map_err(|e| JsError::new(&e.to_string()))?;

        self.emit_progress("REQUEST_COMPLETE", 0.5, "Response received");

        Ok(convert_http_response(core_response))
    }

    /// Returns the transcript of the TLS session.
    pub fn transcript(&self) -> Result<Transcript> {
        let core_transcript = self
            .inner
            .transcript()
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(convert_transcript(core_transcript))
    }

    /// Reveals data to the verifier and finalizes the protocol.
    ///
    /// Optionally accepts a `Commit` object with ranges to hash-commit.
    /// Pass `undefined` or omit the second argument for reveal-only proofs.
    ///
    /// Returns a `RevealOutput` with one `CommitmentOpening` per
    /// hash-committed range (`{ direction, ranges, algorithm, hash, blinder
    /// }`), in the same order as the input `Commit`. The `commitments`
    /// array is empty when no commit was supplied.
    pub async fn reveal(&mut self, reveal: Reveal, commit: Option<Commit>) -> Result<RevealOutput> {
        self.emit_progress("REVEAL", 0.7, "Proving and revealing data...");

        let core_reveal = convert_reveal(reveal);
        let core_commit = commit.map(convert_commit);

        let output = self
            .inner
            .reveal(core_reveal, core_commit)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        self.emit_progress("FINALIZED", 0.95, "Protocol finalized");

        Ok(convert_reveal_output(output))
    }
}

impl JsProver {
    /// Emits a structured progress event to the JS callback (if set).
    fn emit_progress(&self, step: &str, progress: f64, message: &str) {
        if let Some(ref cb) = self.progress_callback {
            let obj = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&obj, &"step".into(), &step.into());
            let _ = js_sys::Reflect::set(&obj, &"progress".into(), &progress.into());
            let _ = js_sys::Reflect::set(&obj, &"message".into(), &message.into());
            let _ = js_sys::Reflect::set(&obj, &"source".into(), &"wasm".into());
            let _ = cb.call1(&JsValue::NULL, &obj);
        }
    }
}

// Conversion functions between WASM types and sdk-core types.

fn convert_prover_config(config: ProverConfig) -> Result<CoreProverConfig> {
    let mut builder = CoreProverConfig::builder(&config.server_name)
        .max_sent_data(config.max_sent_data)
        .max_recv_data(config.max_recv_data)
        .network(match config.network {
            NetworkSetting::Bandwidth => CoreNetworkSetting::Bandwidth,
            NetworkSetting::Latency => CoreNetworkSetting::Latency,
        });

    builder = builder.mode(match config.mode {
        crate::prover::config::ProverMode::Mpc => tlsn_sdk_core::ProverMode::Mpc,
        crate::prover::config::ProverMode::Proxy => tlsn_sdk_core::ProverMode::Proxy,
    });

    if let Some(value) = config.max_sent_records {
        builder = builder.max_sent_records(value);
    }

    if let Some(value) = config.max_recv_data_online {
        builder = builder.max_recv_data_online(value);
    }

    if let Some(value) = config.max_recv_records_online {
        builder = builder.max_recv_records_online(value);
    }

    if let Some(value) = config.defer_decryption_from_start {
        builder = builder.defer_decryption_from_start(value);
    }

    if let Some((certs, key)) = config.client_auth {
        builder = builder.client_auth(certs, key);
    }

    if let Some(root_certs) = config.root_certs {
        builder = builder.root_certs(root_certs);
    }

    builder.build().map_err(|e| JsError::new(&e.to_string()))
}

fn convert_http_request(request: HttpRequest) -> tlsn_sdk_core::HttpRequest {
    let method = match request.method {
        Method::GET => tlsn_sdk_core::Method::GET,
        Method::POST => tlsn_sdk_core::Method::POST,
        Method::PUT => tlsn_sdk_core::Method::PUT,
        Method::DELETE => tlsn_sdk_core::Method::DELETE,
    };

    let mut core_request = tlsn_sdk_core::HttpRequest::new(method, &request.uri);

    for (name, value) in request.headers {
        core_request = core_request.header(name, value);
    }

    if let Some(body) = request.body {
        let core_body = match body {
            Body::Json(value) => tlsn_sdk_core::Body::Json(value),
        };
        core_request = core_request.body(core_body);
    }

    core_request
}

fn convert_http_response(response: tlsn_sdk_core::HttpResponse) -> HttpResponse {
    HttpResponse {
        status: response.status,
        headers: response.headers,
    }
}

fn convert_transcript(transcript: tlsn_sdk_core::Transcript) -> Transcript {
    Transcript {
        sent: transcript.sent,
        recv: transcript.recv,
    }
}

fn convert_hash_algorithm(alg: HashAlgorithm) -> tlsn_sdk_core::HashAlgorithm {
    match alg {
        HashAlgorithm::BLAKE3 => tlsn_sdk_core::HashAlgorithm::Blake3,
        HashAlgorithm::SHA256 => tlsn_sdk_core::HashAlgorithm::Sha256,
        HashAlgorithm::KECCAK256 => tlsn_sdk_core::HashAlgorithm::Keccak256,
    }
}

fn convert_commit_range(cr: CommitRange) -> tlsn_sdk_core::CommitRange {
    tlsn_sdk_core::CommitRange {
        start: cr.start,
        end: cr.end,
        algorithm: convert_hash_algorithm(cr.algorithm),
    }
}

fn convert_commit(commit: Commit) -> tlsn_sdk_core::Commit {
    tlsn_sdk_core::Commit {
        sent: commit.sent.into_iter().map(convert_commit_range).collect(),
        recv: commit.recv.into_iter().map(convert_commit_range).collect(),
    }
}

fn convert_reveal_output(output: tlsn_sdk_core::RevealOutput) -> RevealOutput {
    RevealOutput {
        sent: output.sent.into_iter().map(convert_hash_opening).collect(),
        recv: output.recv.into_iter().map(convert_hash_opening).collect(),
    }
}

fn convert_hash_opening(opening: tlsn_sdk_core::HashOpening) -> HashOpening {
    HashOpening {
        hash: opening.hash,
        blinder: opening.blinder,
    }
}

fn convert_reveal(reveal: Reveal) -> tlsn_sdk_core::Reveal {
    let mut core_reveal = tlsn_sdk_core::Reveal::new();

    for range in reveal.sent {
        core_reveal = core_reveal.sent(range);
    }

    for range in reveal.recv {
        core_reveal = core_reveal.recv(range);
    }

    core_reveal = core_reveal.server_identity(reveal.server_identity);

    core_reveal
}
