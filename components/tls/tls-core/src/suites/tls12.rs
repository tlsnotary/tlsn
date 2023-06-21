use crate::{
    msgs::{
        codec::{Codec, Reader},
        enums::{CipherSuite, SignatureScheme},
        handshake::KeyExchangeAlgorithm,
    },
    suites::{AEADAlgorithm, CipherSuiteCommon, HashAlgorithm, SupportedCipherSuite},
};
use std::fmt;

pub const DOWNGRADE_SENTINEL: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            aead_algorithm: &AEADAlgorithm::CHACHA20_POLY1305,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
        hmac_algorithm: &HashAlgorithm::SHA256,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            aead_algorithm: &AEADAlgorithm::CHACHA20_POLY1305,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        fixed_iv_len: 12,
        explicit_nonce_len: 0,
        hmac_algorithm: &HashAlgorithm::SHA256,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            aead_algorithm: &AEADAlgorithm::AES_128_GCM,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        fixed_iv_len: 4,
        explicit_nonce_len: 8,
        hmac_algorithm: &HashAlgorithm::SHA256,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            aead_algorithm: &AEADAlgorithm::AES_256_GCM,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_RSA_SCHEMES,
        fixed_iv_len: 4,
        explicit_nonce_len: 8,
        hmac_algorithm: &HashAlgorithm::SHA384,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            aead_algorithm: &AEADAlgorithm::AES_128_GCM,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        fixed_iv_len: 4,
        explicit_nonce_len: 8,
        hmac_algorithm: &HashAlgorithm::SHA256,
    });

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
#[cfg(feature = "tls12")]
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls12(&Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            aead_algorithm: &AEADAlgorithm::AES_256_GCM,
        },
        kx: KeyExchangeAlgorithm::ECDHE,
        sign: TLS12_ECDSA_SCHEMES,
        fixed_iv_len: 4,
        explicit_nonce_len: 8,
        hmac_algorithm: &HashAlgorithm::SHA384,
    });

#[cfg(feature = "tls12")]
static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

#[cfg(feature = "tls12")]
static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// A TLS 1.2 cipher suite supported by rustls.
#[cfg(feature = "tls12")]
pub struct Tls12CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,
    pub(crate) hmac_algorithm: &'static super::HashAlgorithm,
    /// How to exchange/agree keys.
    pub kx: KeyExchangeAlgorithm,

    /// How to sign messages for authentication.
    pub sign: &'static [SignatureScheme],

    /// How long the fixed part of the 'IV' is.
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    pub fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub explicit_nonce_len: usize,
}

#[cfg(feature = "tls12")]
impl Tls12CipherSuite {
    /// Resolve the set of supported `SignatureScheme`s from the
    /// offered `SupportedSignatureSchemes`.  If we return an empty
    /// set, the handshake terminates.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        self.sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .cloned()
            .collect()
    }

    /// Which hash function to use with this suite.
    pub fn hash_algorithm(&self) -> &'static super::HashAlgorithm {
        self.hmac_algorithm
    }
}

#[cfg(feature = "tls12")]
impl From<&'static Tls12CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls12CipherSuite) -> Self {
        Self::Tls12(s)
    }
}

#[cfg(feature = "tls12")]
impl PartialEq for Tls12CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

#[cfg(feature = "tls12")]
impl fmt::Debug for Tls12CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls12CipherSuite")
            .field("suite", &self.common.suite)
            .field("algorithm", &self.common.aead_algorithm)
            .finish()
    }
}

pub fn join_randoms(first: &[u8; 32], second: &[u8; 32]) -> [u8; 64] {
    let mut randoms = [0u8; 64];
    randoms[..32].copy_from_slice(first);
    randoms[32..].copy_from_slice(second);
    randoms
}

pub fn decode_ecdh_params<T: Codec>(kx_params: &[u8]) -> Option<T> {
    let mut rd = Reader::init(kx_params);
    let ecdh_params = T::read(&mut rd)?;
    match rd.any_left() {
        false => Some(ecdh_params),
        true => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::{
        enums::NamedGroup,
        handshake::{ClientECDHParams, ServerECDHParams},
    };

    #[test]
    fn server_ecdhe_remaining_bytes() {
        let key = crate::key::PublicKey::new(NamedGroup::secp256r1, &[]);
        let server_params = ServerECDHParams::new(key.group, &key.key);
        let mut server_buf = Vec::new();
        server_params.encode(&mut server_buf);
        server_buf.push(34);
        assert!(decode_ecdh_params::<ServerECDHParams>(&server_buf).is_none());
    }

    #[test]
    fn client_ecdhe_invalid() {
        assert!(decode_ecdh_params::<ClientECDHParams>(&[34]).is_none());
    }
}
