//! A TLS client implementation forked from [rustls](https://github.com/rustls/rustls)
//! version 0.20.
//!
//! Unlike upstream rustls, this client performs no cryptographic operations
//! itself: key exchange, the PRF and record encryption and decryption are
//! delegated to the [`MpcTlsLeader`](crate::MpcTlsLeader), which executes
//! them jointly with the verifier using MPC. The state machine in this
//! module drives the TLS protocol itself: message framing, handshake flow,
//! alerts and connection closure.
//!
//! Only TLS 1.2 cipher suites are currently enabled. The TLS 1.3 message
//! handling inherited from upstream is retained for future use, but is
//! unreachable as long as [`tls_core::versions::ALL_VERSIONS`] excludes
//! TLS 1.3.

#[macro_use]
mod check;
mod config;
mod conn;
mod error;
mod hash_hs;
mod hs;
mod tls12;
mod tls13;
mod vecbuf;

pub(crate) use tls_core::{anchors, verify, x509};

// The public interface is:
pub use crate::client::{
    anchors::RootCertStore,
    config::{ClientConfig, ResolvesClientCert, ServerName},
    conn::{ClientConnection, CommonState, IoState},
    error::Error,
};
pub use tls_core::key::{Certificate, PrivateKey};

/// Message signing interfaces and implementations.
pub mod sign;
