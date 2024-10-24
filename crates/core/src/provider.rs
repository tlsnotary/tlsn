use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    verify::WebPkiVerifier,
};

use crate::{
    hash::HashProvider,
    signing::{SignatureVerifierProvider, SignerProvider},
};

/// Cryptography provider.
///
/// ## Custom Algorithms
///
/// This is the primary interface for extending cryptographic functionality. The
/// various providers can be configured with custom algorithms and
/// implementations.
///
/// Algorithms are uniquely identified using an 8-bit ID, eg.
/// [`HashAlgId`](crate::hash::HashAlgId), half of which is reserved for the
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
    pub cert: WebPkiVerifier,
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
            cert: default_cert_verifier(),
            signer: Default::default(),
            signature: Default::default(),
        }
    }
}

pub(crate) fn default_cert_verifier() -> WebPkiVerifier {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));
    WebPkiVerifier::new(root_store, None)
}
