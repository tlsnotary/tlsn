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

pub(crate) use tls_core::anchors;
mod backend;
mod cipher;
mod conn;
mod error;
mod hash_hs;
mod limited_cache;
mod rand;
mod record_layer;
mod vecbuf;
pub(crate) use tls_core::{verify, x509};
#[macro_use]
mod check;
mod bs_debug;
mod builder;
mod key_log;
mod key_log_file;
mod kx;
mod ticketer;

// The public interface is:
pub use crate::client::{
    anchors::RootCertStore,
    builder::{ConfigBuilder, WantsCipherSuites, WantsKxGroups, WantsVerifier, WantsVersions},
    conn::{CommonState, ConnectionCommon, IoState, Reader, SideData},
    error::Error,
    key_log::{KeyLog, NoKeyLog},
    key_log_file::KeyLogFile,
    kx::{SupportedKxGroup, ALL_KX_GROUPS},
};
pub use backend::{DecryptMode, EncryptMode};
pub use cipher::{MessageDecrypter, MessageEncrypter};
pub use tls_core::{
    key::{Certificate, PrivateKey},
    msgs::{
        enums::{CipherSuite, ProtocolVersion, SignatureScheme},
        handshake::DistinguishedNames,
    },
    suites::{SupportedCipherSuite, ALL_CIPHER_SUITES},
    versions::{SupportedProtocolVersion, ALL_VERSIONS},
};

/// Items for use in a client.
pub mod client {
    pub(super) mod builder;
    mod client_conn;
    mod common;
    pub(super) mod handy;
    mod hs;
    mod tls12;
    mod tls13;

    pub use builder::{WantsClientCert, WantsTransparencyPolicyOrClientCert};
    pub use client_conn::{
        ClientConfig, ClientConnection, ClientConnectionData, InvalidDnsNameError,
        ResolvesClientCert, ServerName, StoresClientSessions,
    };
    pub use handy::{ClientSessionMemoryCache, NoClientSessionStorage};
}

pub use client::{ClientConfig, ClientConnection, ServerName};

/// All defined protocol versions appear in this module.
///
/// ALL_VERSIONS is a provided as an array of all of these values.
pub mod version {
    pub use tls_core::versions::{TLS12, TLS13};
}

/// All defined key exchange groups appear in this module.
///
/// ALL_KX_GROUPS is provided as an array of all of these values.
pub mod kx_group {
    pub use crate::client::kx::{SECP256R1, SECP384R1, X25519};
}

/// Message signing interfaces and implementations.
pub mod sign;
