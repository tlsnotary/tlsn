mod config;
pub mod mock;

pub use config::{
    PRFFollowerConfig, PRFFollowerConfigBuilder, PRFFollowerConfigBuilderError, PRFLeaderConfig,
    PRFLeaderConfigBuilder, PRFLeaderConfigBuilderError,
};

use mpc_circuits::Circuit;
use mpc_core::garble::{ActiveLabels, FullLabels};
use once_cell::sync::Lazy;
use std::sync::Arc;

/// Master secret
///
/// Computes the master secret (MS), returning the outer and inner HMAC states.
///
/// Outer state is H(master_secret ⊕ opad)
///
/// Inner state is H(master_secret ⊕ ipad)
///
/// Inputs:
///
///   0. PMS: 32-byte pre-master secret
///   1. CLIENT_RAND: 32-byte client random
///   2. SERVER_RAND: 32-byte server random
///
/// Outputs:
///
///   0. OUTER_STATE: 32-byte HMAC outer hash state
///   1. INNER_STATE: 32-byte HMAC inner hash state
pub static MS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/master_secret.bin")).unwrap()
});

/// Session Keys
///
/// Compute expanded p1 which consists of client_write_key + server_write_key
/// Compute expanded p2 which consists of client_IV + server_IV
///
/// Inputs:
///
///   0. OUTER_HASH_STATE: 32-byte MS outer-hash state
///   1. INNER_HASH_STATE: 32-byte MS inner-hash state
///   2. CLIENT_RAND: 32-byte client random
///   3. SERVER_RAND: 32-byte server random
///
/// Outputs:
///
///   0. CWK: 16-byte client write-key
///   1. SWK: 16-byte server write-key
///   2. CIV: 4-byte client IV
///   3. SIV: 4-byte server IV
pub static SESSION_KEYS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/session_keys.bin")).unwrap()
});

/// Computes client finished verify_data as specified in RFC 5246, Section 7.4.9.
///
/// Inputs:
///
///   0. OUTER_STATE: 32-byte MS outer-hash state H(ms ⊕ opad)
///   1. INNER_STATE: 32-byte MS inner-hash state H(ms ⊕ ipad)
///   2. HS_HASH: 32-byte handshake hash
///   3. MASK: 12-byte mask for verify_data
///
/// Outputs:
///
///   0. MASKED_VD: 12-byte masked client finished verify_data (VD + MASK)
pub static CF_VD: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/cf_verify_data.bin")).unwrap()
});

/// Computes server finished verify_data as specified in RFC 5246, Section 7.4.9.
///
/// Inputs:
///
///   0. OUTER_STATE: 32-byte MS outer-hash state H(ms ⊕ opad)
///   1. INNER_STATE: 32-byte MS inner-hash state H(ms ⊕ ipad)
///   2. HS_HASH: 32-byte handshake hash
///   3. MASK: 12-byte mask for verify_data
///
/// Outputs:
///
///   0. MASKED_VD: 12-byte masked server finished verify_data (VD + MASK)
pub static SF_VD: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/sf_verify_data.bin")).unwrap()
});

#[derive(Debug, Clone)]
pub struct PmsLabels {
    pub full: FullLabels,
    pub active: ActiveLabels,
}

#[derive(Debug, Clone)]
pub struct MasterSecretStateLabels {
    pub full_outer_hash_state: FullLabels,
    pub full_inner_hash_state: FullLabels,
    pub active_outer_hash_state: ActiveLabels,
    pub active_inner_hash_state: ActiveLabels,
    pub full_client_random: FullLabels,
    pub full_server_random: FullLabels,
    pub active_client_random: ActiveLabels,
    pub active_server_random: ActiveLabels,
    pub full_const_zero: FullLabels,
    pub full_const_one: FullLabels,
    pub active_const_zero: ActiveLabels,
    pub active_const_one: ActiveLabels,
}

#[derive(Debug, Clone)]
pub struct SessionKeyLabels {
    pub full_cwk: FullLabels,
    pub full_swk: FullLabels,
    pub full_civ: FullLabels,
    pub full_siv: FullLabels,
    pub active_cwk: ActiveLabels,
    pub active_swk: ActiveLabels,
    pub active_civ: ActiveLabels,
    pub active_siv: ActiveLabels,
}
