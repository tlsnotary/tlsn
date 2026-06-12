//! TLS handshake protocol, forked from [rustls](https://github.com/rustls/rustls)
//! version 0.20.
//!
//! This module provides everything needed to perform the TLS handshake under
//! the [`MpcTlsLeader`](crate::MpcTlsLeader): the handshake state machine
//! ([`hs`], [`tls12`], [`tls13`]), client configuration, certificate
//! verification and message signing. Unlike upstream rustls the client performs
//! no cryptographic operations itself — the key exchange, the PRF and record
//! encryption/decryption are delegated to the MPC session owned by the leader.
//! The state machine operates directly on the live connection ([`crate::conn`]'s
//! `Conn`). Post-handshake (online) message routing lives on
//! [`Conn`](crate::conn::Conn), not here.
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

pub(crate) use tls_core::{anchors, verify, x509};

// Public TLS-policy types. These are re-exported at the crate root, which is
// the public path; see `crate::lib`.
pub use crate::handshake::{
    anchors::RootCertStore,
    config::{ClientConfig, ResolvesClientCert, ServerName},
    error::Error,
};
pub use tls_core::key::{Certificate, PrivateKey};

/// Message signing interfaces and implementations.
pub mod sign;
