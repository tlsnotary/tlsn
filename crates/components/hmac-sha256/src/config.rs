//! Modes of operation.

/// Modes for the TLS 1.2 PRF and the TLS 1.3 key schedule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    /// Computes some hashes locally.
    Reduced,
    /// Computes the whole function in MPC.
    Normal,
}
