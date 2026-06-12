//! TLS client protocol layer, forked from [rustls](https://github.com/rustls/rustls)
//! version 0.20.
//!
//! This module provides the TLS-specific pieces driven by the
//! [`MpcTlsLeader`](crate::MpcTlsLeader): client configuration and certificate
//! verification, message signing, and the handshake state machine. Unlike
//! upstream rustls the client performs no cryptographic operations itself — the
//! key exchange, the PRF and record encryption/decryption are delegated to the
//! MPC session owned by the leader. The handshake state machine in [`hs`],
//! [`tls12`] and [`tls13`] drives the TLS protocol itself, operating directly
//! on the live connection.
//!
//! Only TLS 1.2 cipher suites are currently enabled. The TLS 1.3 message
//! handling inherited from upstream is retained for future use, but is
//! unreachable as long as [`tls_core::versions::ALL_VERSIONS`] excludes
//! TLS 1.3.

#[macro_use]
mod check;
mod config;
pub(crate) mod error;
pub(crate) mod hash_hs;
pub(crate) mod hs;
pub(crate) mod tls12;
pub(crate) mod tls13;
pub(crate) mod vecbuf;

pub(crate) use tls_core::{anchors, verify, x509};

// The public interface is:
pub use crate::client::{
    anchors::RootCertStore,
    config::{ClientConfig, ResolvesClientCert, ServerName},
    error::Error,
};
pub use tls_core::key::{Certificate, PrivateKey};

/// Message signing interfaces and implementations.
pub mod sign;
