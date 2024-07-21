use crate::msgs::enums::NamedGroup;
use std::fmt;

/// This type contains a private key by value.
///
/// The private key must be DER-encoded ASN.1 in either
/// PKCS#8 or PKCS#1 format.
///
/// The `rustls-pemfile` crate can be used to extract
/// private keys from a PEM file in these formats.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateKey(pub Vec<u8>);

/// This type contains a single certificate by value.
///
/// The certificate must be DER-encoded X.509.
///
/// The `rustls-pemfile` crate can be used to parse a PEM file.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Certificate(pub Vec<u8>);

impl AsRef<[u8]> for Certificate {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::utils::BsDebug;
        f.debug_tuple("Certificate")
            .field(&BsDebug(&self.0))
            .finish()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey {
    pub group: NamedGroup,
    pub key: Vec<u8>,
}

impl PublicKey {
    pub fn new(group: NamedGroup, key: &[u8]) -> Self {
        Self {
            group,
            key: Vec::from(key),
        }
    }
}

impl From<crate::msgs::handshake::KeyShareEntry> for PublicKey {
    #[inline]
    fn from(k: crate::msgs::handshake::KeyShareEntry) -> Self {
        Self {
            group: k.group,
            key: k.payload.0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::Certificate;

    #[test]
    fn certificate_debug() {
        assert_eq!(
            "Certificate(b\"ab\")",
            format!("{:?}", Certificate(b"ab".to_vec()))
        );
    }
}
