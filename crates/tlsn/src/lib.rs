//! TLSNotary library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod commit;
pub(crate) mod context;
pub(crate) mod encoding;
pub(crate) mod ghash;
pub(crate) mod msg;
pub(crate) mod mux;
pub mod prover;
pub(crate) mod tag;
pub mod verifier;
pub(crate) mod zk_aes_ctr;

pub use tlsn_attestation as attestation;
pub use tlsn_core::{config, connection, hash, transcript, webpki};

/// The party's role in the TLSN protocol.
///
/// A Notary is classified as a Verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// The prover.
    Prover,
    /// The verifier.
    Verifier,
}

use mpc_tls::Config;
use tlsn_core::config::{NetworkSetting, ProtocolConfig};

pub(crate) fn build_mpc_tls_config(config: &ProtocolConfig) -> Config {
    let mut builder = Config::builder();

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
