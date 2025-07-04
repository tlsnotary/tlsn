use serde::{Deserialize, Serialize};

/// Custom HTTP header used for specifying a whitelisted API key.
pub const X_API_KEY_HEADER: &str = "X-API-Key";

/// Types of client that the prover is using.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClientType {
    /// Client that has access to the transport layer.
    Tcp,
    /// Client that cannot directly access the transport layer, e.g. browser
    /// extension.
    Websocket,
}

/// Request object of the /session API.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionRequest {
    pub client_type: ClientType,
    /// Maximum data that can be sent by the prover.
    pub max_sent_data: Option<usize>,
    /// Maximum data that can be received by the prover.
    pub max_recv_data: Option<usize>,
}

/// Response object of the /session API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationSessionResponse {
    /// Unique session id that is generated by the notary and shared to the
    /// prover.
    pub session_id: String,
}
