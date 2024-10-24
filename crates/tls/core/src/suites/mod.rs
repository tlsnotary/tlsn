pub mod tls12;
pub mod tls13;

#[cfg(feature = "tls12")]
use crate::versions::TLS12;
use crate::{
    msgs::{
        enums::{CipherSuite, ProtocolVersion, SignatureAlgorithm, SignatureScheme},
        handshake::DecomposedSignatureScheme,
    },
    versions::{SupportedProtocolVersion, TLS13},
};
#[cfg(feature = "tls12")]
pub use tls12::Tls12CipherSuite;
#[cfg(feature = "tls12")]
pub use tls12::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    // TLS1.2 suites
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};
pub use tls13::{
    Tls13CipherSuite, TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
};

/// AEAD Algorithm scheme used by a cipher suite.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum AEADAlgorithm {
    /// AES with 128-bit keys in Galois counter mode.
    AES_128_GCM,

    /// AES with 256-bit keys in Galois counter mode.
    AES_256_GCM,

    /// Chacha20 for confidentiality with poly1305 for authenticity.
    CHACHA20_POLY1305,
}

/// Hash algorithm used by a cipher suite.
#[derive(Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA512_256,
}

impl HashAlgorithm {
    pub fn output_len(&self) -> usize {
        match self {
            HashAlgorithm::SHA1 => 20,
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            HashAlgorithm::SHA512 => 64,
            HashAlgorithm::SHA512_256 => 32,
        }
    }
}

/// Hash-based Key Derivation Function algorithm used by a cipher suite.
#[derive(Debug, Eq, PartialEq)]
pub enum HKDFAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

impl HKDFAlgorithm {
    fn hash_algorithm(&self) -> &'static HashAlgorithm {
        match self {
            HKDFAlgorithm::SHA1 => &HashAlgorithm::SHA1,
            HKDFAlgorithm::SHA256 => &HashAlgorithm::SHA256,
            HKDFAlgorithm::SHA384 => &HashAlgorithm::SHA384,
            HKDFAlgorithm::SHA512 => &HashAlgorithm::SHA512,
        }
    }
}

/// Common state for cipher suites (both for TLS 1.2 and TLS 1.3)
pub struct CipherSuiteCommon {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,
    pub aead_algorithm: &'static AEADAlgorithm,
}

/// A cipher suite supported by rustls.
///
/// All possible instances of this type are provided by the library in
/// the [`ALL_CIPHER_SUITES`] array.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SupportedCipherSuite {
    /// A TLS 1.2 cipher suite
    #[cfg(feature = "tls12")]
    Tls12(&'static Tls12CipherSuite),
    /// A TLS 1.3 cipher suite
    Tls13(&'static Tls13CipherSuite),
}

impl SupportedCipherSuite {
    /// Which hash function to use with this suite.
    pub fn hash_algorithm(&self) -> &'static HashAlgorithm {
        match self {
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(inner) => inner.hash_algorithm(),
            SupportedCipherSuite::Tls13(inner) => inner.hash_algorithm(),
        }
    }

    /// The cipher suite's identifier
    pub fn suite(&self) -> CipherSuite {
        self.common().suite
    }

    pub(crate) fn common(&self) -> &CipherSuiteCommon {
        match self {
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(inner) => &inner.common,
            SupportedCipherSuite::Tls13(inner) => &inner.common,
        }
    }

    pub fn tls13(&self) -> Option<&'static Tls13CipherSuite> {
        match self {
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(_) => None,
            SupportedCipherSuite::Tls13(inner) => Some(inner),
        }
    }

    /// Return supported protocol version for the cipher suite.
    pub fn version(&self) -> &'static SupportedProtocolVersion {
        match self {
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(_) => &TLS12,
            SupportedCipherSuite::Tls13(_) => &TLS13,
        }
    }

    /// Return true if this suite is usable for a key only offering `sig_alg`
    /// signatures.  This resolves to true for all TLS1.3 suites.
    pub fn usable_for_signature_algorithm(&self, _sig_alg: SignatureAlgorithm) -> bool {
        match self {
            SupportedCipherSuite::Tls13(_) => true, // no constraint expressed by ciphersuite (e.g., TLS1.3)
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(inner) => {
                inner.sign.iter().any(|scheme| scheme.sign() == _sig_alg)
            }
        }
    }
}

/// A list of all the cipher suites supported by rustls.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // // TLS1.3 suites
    // TLS13_AES_256_GCM_SHA384,
    // TLS13_AES_128_GCM_SHA256,
    // TLS13_CHACHA20_POLY1305_SHA256,
    // TLS1.2 suites
    // #[cfg(feature = "tls12")]
    // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    // #[cfg(feature = "tls12")]
    // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    // #[cfg(feature = "tls12")]
    // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    #[cfg(feature = "tls12")]
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    // #[cfg(feature = "tls12")]
    // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The cipher suite configuration that an application should use by default.
///
/// This will be [`ALL_CIPHER_SUITES`] sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

// These both O(N^2)!
pub fn choose_ciphersuite_preferring_client(
    client_suites: &[CipherSuite],
    server_suites: &[SupportedCipherSuite],
) -> Option<SupportedCipherSuite> {
    for client_suite in client_suites {
        if let Some(selected) = server_suites.iter().find(|x| *client_suite == x.suite()) {
            return Some(*selected);
        }
    }

    None
}

pub fn choose_ciphersuite_preferring_server(
    client_suites: &[CipherSuite],
    server_suites: &[SupportedCipherSuite],
) -> Option<SupportedCipherSuite> {
    if let Some(selected) = server_suites
        .iter()
        .find(|x| client_suites.contains(&x.suite()))
    {
        return Some(*selected);
    }

    None
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with `SignatureAlgorithm` `sigalg` removed.
pub fn reduce_given_sigalg(
    all: &[SupportedCipherSuite],
    sigalg: SignatureAlgorithm,
) -> Vec<SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_signature_algorithm(sigalg))
        .copied()
        .collect()
}

/// Return a list of the ciphersuites in `all` with the suites
/// incompatible with the chosen `version` removed.
pub fn reduce_given_version(
    all: &[SupportedCipherSuite],
    version: ProtocolVersion,
) -> Vec<SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.version().version == version)
        .copied()
        .collect()
}

/// Return true if `sigscheme` is usable by any of the given suites.
pub fn compatible_sigscheme_for_suites(
    sigscheme: SignatureScheme,
    common_suites: &[SupportedCipherSuite],
) -> bool {
    let sigalg = sigscheme.sign();
    common_suites
        .iter()
        .any(|&suite| suite.usable_for_signature_algorithm(sigalg))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::msgs::enums::CipherSuite;

    #[test]
    fn test_client_pref() {
        let client = vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ];
        let server = vec![TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];
        let chosen = choose_ciphersuite_preferring_client(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), TLS13_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_server_pref() {
        let client = vec![
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ];
        let server = vec![TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];
        let chosen = choose_ciphersuite_preferring_server(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(chosen.unwrap(), TLS13_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_pref_fails() {
        assert!(choose_ciphersuite_preferring_client(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            ALL_CIPHER_SUITES
        )
        .is_none());
        assert!(choose_ciphersuite_preferring_server(
            &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
            ALL_CIPHER_SUITES
        )
        .is_none());
    }

    #[test]
    fn test_scs_is_debug() {
        println!("{:?}", ALL_CIPHER_SUITES);
    }
}
