//! PRF Config.

/// Configuration option for the PRF.
#[derive(Debug, Clone, Copy)]
pub enum Config {
    /// Computes some hashes locally.
    Local,
    /// Computes the whole PRF in MPC.
    Mpc,
}

impl Default for Config {
    fn default() -> Self {
        Self::Mpc
    }
}
