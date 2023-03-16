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

pub static MS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/master_secret.bin")).unwrap()
});
pub static SESSION_KEYS: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/session_keys.bin")).unwrap()
});
pub static CF_VD: Lazy<Arc<Circuit>> = Lazy::new(|| {
    Circuit::load_bytes(std::include_bytes!("../circuits/bin/cf_verify_data.bin")).unwrap()
});
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
