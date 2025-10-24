use super::*;

pub(crate) mod config;

/// Output of the prover plugin.
pub struct Output {
    prover_output: ProverOutput,
    /// Plaintext exposed to the host.
    exposed: Vec<(ExposeHandle, Vec<u8>)>,
}

pub struct ProverParams {
    maxRecvData: usize,
    maxSentData: usize,
    pub serverDns: String,
    verifierUrl: String,
    // Proxy to use to connect to the server.
    proxyUrl: Option<String>,
}

pub struct RequestParams {
    url: String,
    method: String,
    body: Option<Vec<u8>>,
    pub headers: Vec<(String, String)>,
}

/// Handle for a part of HTTP message which will be exposed to the
/// plugin's host.
#[derive(PartialEq, Clone)]
pub struct ExposeHandle {
    typ: MessageType,
    part: MessagePart,
    params: Option<PartParams>,
}
