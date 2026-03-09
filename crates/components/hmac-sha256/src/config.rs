//! PRF configuration.

/// Network mode for the PRF.
#[derive(Debug, Clone, Copy)]
pub enum NetworkMode {
    /// Computes some hashes locally.
    Reduced,
    /// Computes the whole PRF in MPC.
    Normal,
}

/// Master secret derivation mode.
#[derive(Debug, Clone, Copy)]
pub enum MSMode {
    /// Standard master secret derivation using `client_random || server_random`.
    Standard,
    /// Extended Master Secret (RFC 7627) using session hash.
    Extended,
}

/// PRF configuration.
#[derive(Debug, Clone, Copy)]
pub struct PrfConfig {
    /// Network mode.
    pub network: NetworkMode,
    /// Master secret derivation mode.
    pub ms: MSMode,
}

impl PrfConfig {
    /// Creates a new PRF configuration.
    pub fn new(network: NetworkMode, ms: MSMode) -> Self {
        Self { network, ms }
    }
}
