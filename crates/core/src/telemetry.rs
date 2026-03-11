//! Benchmark telemetry types shared across TLSNotary crates.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// A stable benchmark phase name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BenchPhase {
    /// MPC-TLS preprocessing, including concurrent setup work.
    PreprocessSetup,
    /// Online key exchange setup and completion.
    ///
    /// This phase may occur more than once during a handshake when completion is
    /// deferred until dependent VM work has finished.
    HandshakeKeOnline,
    /// PRF work for handshake/session key derivation.
    HandshakePrfSessionKeys,
    /// Record-layer setup after handshake keys are ready.
    HandshakeRecordSetup,
    /// PRF work for the server `Finished` verification data.
    HandshakePrfServerFinished,
    /// PRF work for the client `Finished` verification data.
    HandshakePrfClientFinished,
    /// Record-layer flush work that performs at least one encrypt/decrypt op.
    RecordLayerFlush,
    /// TLS authentication finalization after the socket closes.
    FinalizeTlsAuth,
    /// Transcript proving, including setup, VM execution, and finalization.
    ProveTranscript,
}

impl BenchPhase {
    /// All benchmark phases in stable serialization order.
    pub const ALL: [Self; 9] = [
        Self::PreprocessSetup,
        Self::HandshakeKeOnline,
        Self::HandshakePrfSessionKeys,
        Self::HandshakeRecordSetup,
        Self::HandshakePrfServerFinished,
        Self::HandshakePrfClientFinished,
        Self::RecordLayerFlush,
        Self::FinalizeTlsAuth,
        Self::ProveTranscript,
    ];

    /// Returns the stable string form for this phase.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreprocessSetup => "preprocess_setup",
            Self::HandshakeKeOnline => "handshake_ke_online",
            Self::HandshakePrfSessionKeys => "handshake_prf_session_keys",
            Self::HandshakeRecordSetup => "handshake_record_setup",
            Self::HandshakePrfServerFinished => "handshake_prf_server_finished",
            Self::HandshakePrfClientFinished => "handshake_prf_client_finished",
            Self::RecordLayerFlush => "record_layer_flush",
            Self::FinalizeTlsAuth => "finalize_tls_auth",
            Self::ProveTranscript => "prove_transcript",
        }
    }
}

impl Serialize for BenchPhase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BenchPhase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;
        match value {
            "preprocess_setup" => Ok(Self::PreprocessSetup),
            "handshake_ke_online" => Ok(Self::HandshakeKeOnline),
            "handshake_prf_session_keys" => Ok(Self::HandshakePrfSessionKeys),
            "handshake_record_setup" => Ok(Self::HandshakeRecordSetup),
            "handshake_prf_server_finished" => Ok(Self::HandshakePrfServerFinished),
            "handshake_prf_client_finished" => Ok(Self::HandshakePrfClientFinished),
            "record_layer_flush" => Ok(Self::RecordLayerFlush),
            "finalize_tls_auth" => Ok(Self::FinalizeTlsAuth),
            "prove_transcript" => Ok(Self::ProveTranscript),
            _ => Err(D::Error::custom(format!("unknown benchmark phase: {value}"))),
        }
    }
}

/// A phase lifecycle event emitted by benchmark instrumentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseEvent {
    /// The phase started.
    Start,
    /// The phase ended.
    End,
}

/// Receives benchmark phase events.
pub trait TelemetrySink: Send + Sync + 'static {
    /// Records a benchmark phase lifecycle event.
    fn phase_event(&self, phase: BenchPhase, event: PhaseEvent);
}
