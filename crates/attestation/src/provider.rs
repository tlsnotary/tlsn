use tlsn_core::{hash::HashProvider, webpki::ServerCertVerifier};

use crate::signing::{SignatureVerifierProvider, SignerProvider};

/// Cryptography provider.
///
/// ## Custom Algorithms
///
/// This is the primary interface for extending cryptographic functionality. The
/// various providers can be configured with custom algorithms and
/// implementations.
///
/// Algorithms are uniquely identified using an 8-bit ID, eg.
/// [`HashAlgId`](tlsn_core::hash::HashAlgId), half of which is reserved for the
/// officially supported algorithms. If you think that a new algorithm should be
/// added to the official set, please open an issue. Beware that other parties
/// may assign different algorithms to the same ID as you, and we make no effort
/// to mitigate this.
pub struct CryptoProvider {
    /// Hash provider.
    pub hash: HashProvider,
    /// Certificate verifier.
    ///
    /// This is used to verify the server's certificate chain.
    ///
    /// The default verifier uses the Mozilla root certificates.
    pub cert: ServerCertVerifier,
    /// Signer provider.
    ///
    /// This is used for signing attestations.
    pub signer: SignerProvider,
    /// Signature verifier provider.
    ///
    /// This is used for verifying signatures of attestations.
    pub signature: SignatureVerifierProvider,
}

opaque_debug::implement!(CryptoProvider);

impl Default for CryptoProvider {
    fn default() -> Self {
        Self {
            hash: Default::default(),
            cert: ServerCertVerifier::mozilla(),
            signer: Default::default(),
            signature: Default::default(),
        }
    }
}
