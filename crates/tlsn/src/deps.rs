use mpc_tls::SessionKeys;
use tlsn_core::config::tls_commit::mpc::{MpcTlsConfig, NetworkSetting};
use tlsn_deap::Deap;

mod prover;
pub(crate) use prover::{ProverDeps, ProverMpc, ProverZk};

mod verifier;
pub(crate) use verifier::{VerifierDeps, VerifierZk};

fn build_mpc_tls_config(config: &MpcTlsConfig) -> mpc_tls::Config {
    let mut builder = mpc_tls::Config::builder();

    builder
        .defer_decryption(config.defer_decryption_from_start())
        .max_sent(config.max_sent_data())
        .max_recv_online(config.max_recv_data_online())
        .max_recv(config.max_recv_data());

    if let Some(max_sent_records) = config.max_sent_records() {
        builder.max_sent_records(max_sent_records);
    }

    if let Some(max_recv_records_online) = config.max_recv_records_online() {
        builder.max_recv_records_online(max_recv_records_online);
    }

    if let NetworkSetting::Latency = config.network() {
        builder.low_bandwidth();
    }

    builder.build().unwrap()
}

fn translate_keys<Mpc, Zk>(keys: &mut SessionKeys, vm: &Deap<Mpc, Zk>) {
    keys.client_write_key = vm
        .translate(keys.client_write_key)
        .expect("VM memory should be consistent");
    keys.client_write_iv = vm
        .translate(keys.client_write_iv)
        .expect("VM memory should be consistent");
    keys.server_write_key = vm
        .translate(keys.server_write_key)
        .expect("VM memory should be consistent");
    keys.server_write_iv = vm
        .translate(keys.server_write_iv)
        .expect("VM memory should be consistent");
    keys.server_write_mac_key = vm
        .translate(keys.server_write_mac_key)
        .expect("VM memory should be consistent");
}
