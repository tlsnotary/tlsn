use crate::{
    error::Error,
    x509::{wrap_in_asn1_len, wrap_in_sequence},
};
use p256::{
    ecdsa::{signature::Signer as _, SigningKey as EcdsaKey},
    pkcs8::DecodePrivateKey,
};
use std::{convert::TryFrom, error::Error as StdError, fmt, sync::Arc};
use tls_core::{
    key,
    msgs::enums::{SignatureAlgorithm, SignatureScheme},
    x509::Tag,
};

/// An abstract signing key.
pub trait SigningKey: Send + Sync {
    /// Choose a `SignatureScheme` from those offered.
    ///
    /// Expresses the choice by returning something that implements `Signer`,
    /// using the chosen scheme.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A thing that can sign a message.
pub trait Signer: Send + Sync {
    /// Signs `message` using the selected scheme.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reveals which scheme will be used when you call `sign()`.
    fn scheme(&self) -> SignatureScheme;
}

/// A packaged-together certificate chain, matching `SigningKey` and
/// optional stapled OCSP response and/or SCT list.
#[derive(Clone)]
pub struct CertifiedKey {
    /// The certificate chain.
    pub cert: Vec<tls_core::key::Certificate>,

    /// The certified key.
    pub key: Arc<dyn SigningKey>,

    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Vec<u8>>,

    /// An optional collection of SCTs from CT logs, proving the
    /// certificate is included on those logs.  This must be
    /// a `SignedCertificateTimestampList` encoding; see RFC6962.
    pub sct_list: Option<Vec<u8>>,
}

impl CertifiedKey {
    /// Make a new CertifiedKey, with the given chain and key.
    ///
    /// The cert chain must not be empty. The first certificate in the chain
    /// must be the end-entity certificate.
    pub fn new(cert: Vec<tls_core::key::Certificate>, key: Arc<dyn SigningKey>) -> Self {
        Self {
            cert,
            key,
            ocsp: None,
            sct_list: None,
        }
    }

    /// The end-entity certificate.
    pub fn end_entity_cert(&self) -> Result<&tls_core::key::Certificate, SignError> {
        self.cert.get(0).ok_or(SignError(()))
    }

    /// Check the certificate chain for validity:
    /// - it should be non-empty list
    /// - the first certificate should be parsable as a x509v3,
    /// - the first certificate should quote the given server name
    ///   (if provided)
    ///
    /// These checks are not security-sensitive.  They are the
    /// *server* attempting to detect accidental misconfiguration.
    pub(crate) fn cross_check_end_entity_cert(
        &self,
        name: Option<webpki::DnsNameRef>,
    ) -> Result<(), Error> {
        // Always reject an empty certificate chain.
        let end_entity_cert = self.end_entity_cert().map_err(|SignError(())| {
            Error::General("No end-entity certificate in certificate chain".to_string())
        })?;

        // Reject syntactically-invalid end-entity certificates.
        let end_entity_cert =
            webpki::EndEntityCert::try_from(end_entity_cert.as_ref()).map_err(|_| {
                Error::General(
                    "End-entity certificate in certificate \
                                  chain is syntactically invalid"
                        .to_string(),
                )
            })?;

        if let Some(name) = name {
            // If SNI was offered then the certificate must be valid for
            // that hostname. Note that this doesn't fully validate that the
            // certificate is valid; it only validates that the name is one
            // that the certificate is valid for, if the certificate is
            // valid.
            if end_entity_cert.verify_is_valid_for_dns_name(name).is_err() {
                return Err(Error::General(
                    "The server certificate is not \
                                             valid for the given name"
                        .to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Parse `der` as any supported key encoding/type, returning
/// the first which works.
pub fn any_supported_type(der: &key::PrivateKey) -> Result<Arc<dyn SigningKey>, SignError> {
    any_ecdsa_type(der)
}

/// Parse `der` as any ECDSA key type, returning the first which works.
///
/// Both SEC1 (PEM section starting with 'BEGIN EC PRIVATE KEY') and PKCS8
/// (PEM section starting with 'BEGIN PRIVATE KEY') encodings are supported.
pub fn any_ecdsa_type(der: &key::PrivateKey) -> Result<Arc<dyn SigningKey>, SignError> {
    if let Ok(ecdsa_p256) = EcdsaSigningKey::new(der, SignatureScheme::ECDSA_NISTP256_SHA256) {
        return Ok(Arc::new(ecdsa_p256));
    }

    if let Ok(ecdsa_p384) = EcdsaSigningKey::new(der, SignatureScheme::ECDSA_NISTP384_SHA384) {
        return Ok(Arc::new(ecdsa_p384));
    }

    Err(SignError(()))
}

/// A SigningKey that uses exactly one TLS-level SignatureScheme
/// and one ring-level signature::SigningAlgorithm.
///
/// Compare this to RsaSigningKey, which for a particular key is
/// willing to sign with several algorithms.  This is quite poor
/// cryptography practice, but is necessary because a given RSA key
/// is expected to work in TLS1.2 (PKCS#1 signatures) and TLS1.3
/// (PSS signatures) -- nobody is willing to obtain certificates for
/// different protocol versions.
///
/// Currently this is only implemented for ECDSA keys.
struct EcdsaSigningKey {
    key: Arc<EcdsaKey>,
    scheme: SignatureScheme,
}

impl EcdsaSigningKey {
    /// Make a new `ECDSASigningKey` from a DER encoding in PKCS#8 or SEC1
    /// format, expecting a key usable with precisely the given signature
    /// scheme.
    fn new(der: &key::PrivateKey, scheme: SignatureScheme) -> Result<Self, ()> {
        // We only support ECDSA_NISTP256_SHA256
        match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {}
            _ => return Err(()), // all callers are in this file
        }

        p256::SecretKey::from_pkcs8_der(&der.0)
            .or_else(|_| p256::SecretKey::from_sec1_der(&der.0))
            .map_err(|_| ())
            .map(|kp| Self {
                key: Arc::new(kp.into()),
                scheme,
            })
    }
}

// This is (line-by-line):
// - INTEGER Version = 0
// - SEQUENCE (privateKeyAlgorithm)
//   - id-ecPublicKey OID
//   - prime256v1 OID
const PKCS8_PREFIX_ECDSA_NISTP256: &[u8] = b"\x02\x01\x00\
      \x30\x13\
      \x06\x07\x2a\x86\x48\xce\x3d\x02\x01\
      \x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(EcdsaSigner {
                key: Arc::clone(&self.key),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        use tls_core::msgs::handshake::DecomposedSignatureScheme;
        self.scheme.sign()
    }
}

struct EcdsaSigner {
    key: Arc<EcdsaKey>,
    scheme: SignatureScheme,
}

impl Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(
            p256::ecdsa::signature::Signer::<p256::ecdsa::Signature>::sign(&(*self.key), message)
                .to_vec(),
        )
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// The set of schemes we support for signatures and
/// that are allowed for TLS1.3.
pub fn supported_sign_tls13() -> &'static [SignatureScheme] {
    &[SignatureScheme::ECDSA_NISTP256_SHA256]
}

/// Errors while signing
#[derive(Debug)]
pub struct SignError(());

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("sign error")
    }
}

impl StdError for SignError {}

#[test]
fn can_load_ecdsa_nistp256_pkcs8() {
    let key = key::PrivateKey(include_bytes!("testdata/nistp256key.pkcs8.der").to_vec());
    assert!(any_supported_type(&key).is_ok());
    assert!(any_ecdsa_type(&key).is_ok());
}

#[test]
fn can_load_ecdsa_nistp256_sec1() {
    let key = key::PrivateKey(include_bytes!("testdata/nistp256key.der").to_vec());
    assert!(any_supported_type(&key).is_ok());
    assert!(any_ecdsa_type(&key).is_ok());
}
