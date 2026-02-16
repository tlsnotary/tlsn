//! WASM Verifier bindings.

mod config;

pub use config::VerifierConfig;

use tlsn_sdk_core::{SdkVerifier, VerifierConfig as CoreVerifierConfig};
use wasm_bindgen::prelude::*;

use crate::{
    io::{JsIo, JsIoAdapter},
    types::VerifierOutput,
};

type Result<T> = std::result::Result<T, JsError>;

/// Verifier for the TLSNotary protocol.
///
/// The verifier participates in the MPC-TLS protocol with the prover,
/// verifying the authenticity of the TLS session without seeing the
/// full plaintext.
#[wasm_bindgen(js_name = Verifier)]
pub struct JsVerifier {
    inner: SdkVerifier,
}

#[wasm_bindgen(js_class = Verifier)]
impl JsVerifier {
    /// Creates a new Verifier with the given configuration.
    #[wasm_bindgen(constructor)]
    pub fn new(config: VerifierConfig) -> JsVerifier {
        let core_config = convert_verifier_config(config);
        let inner = SdkVerifier::new(core_config);
        JsVerifier { inner }
    }

    /// Connects to the prover.
    ///
    /// # Arguments
    ///
    /// * `prover_io` - A JavaScript object implementing the IoChannel
    ///   interface, connected to the prover.
    pub async fn connect(&mut self, prover_io: JsIo) -> Result<()> {
        let adapter = JsIoAdapter::new(prover_io);
        self.inner
            .connect(adapter.into_boxed())
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Verifies the connection and finalizes the protocol.
    pub async fn verify(&mut self) -> Result<VerifierOutput> {
        let core_output = self
            .inner
            .verify()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(convert_verifier_output(core_output))
    }
}

// Conversion functions between WASM types and sdk-core types.

fn convert_verifier_config(config: VerifierConfig) -> CoreVerifierConfig {
    let mut builder = CoreVerifierConfig::builder()
        .max_sent_data(config.max_sent_data)
        .max_recv_data(config.max_recv_data);

    if let Some(value) = config.max_sent_records {
        builder = builder.max_sent_records(value);
    }

    if let Some(value) = config.max_recv_records_online {
        builder = builder.max_recv_records_online(value);
    }

    builder.build()
}

fn convert_verifier_output(output: tlsn_sdk_core::VerifierOutput) -> VerifierOutput {
    VerifierOutput {
        server_name: output.server_name,
        connection_info: crate::types::ConnectionInfo {
            time: output.connection_info.time,
            version: match output.connection_info.version {
                tlsn_sdk_core::TlsVersion::V1_2 => crate::types::TlsVersion::V1_2,
                tlsn_sdk_core::TlsVersion::V1_3 => crate::types::TlsVersion::V1_3,
            },
            transcript_length: crate::types::TranscriptLength {
                sent: output.connection_info.transcript_length.sent,
                recv: output.connection_info.transcript_length.recv,
            },
        },
        transcript: output.transcript.map(|t| crate::types::PartialTranscript {
            sent: t.sent,
            sent_authed: t.sent_authed,
            recv: t.recv,
            recv_authed: t.recv_authed,
        }),
    }
}
