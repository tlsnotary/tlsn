/// Canonical serialization of TLSNotary types.
///
/// This trait is used to serialize types into a canonical byte representation.
pub(crate) trait CanonicalSerialize {
    /// Serializes the type.
    fn serialize(&self) -> Vec<u8>;
}

impl<T> CanonicalSerialize for T
where
    T: serde::Serialize,
{
    fn serialize(&self) -> Vec<u8> {
        // For now we use BCS for serialization. In future releases we will want to
        // consider this further, particularly with respect to EVM compatibility.
        bcs::to_bytes(self).unwrap()
    }
}

/// A type with a domain separator which is used during hashing to mitigate type
/// confusion attacks.
pub(crate) trait DomainSeparator {
    /// Returns the domain separator for the type.
    fn domain(&self) -> &[u8];
}

macro_rules! impl_domain_separator {
    ($type:ty) => {
        impl $crate::serialize::DomainSeparator for $type {
            fn domain(&self) -> &[u8] {
                use std::sync::LazyLock;

                // Computes a 16 byte hash of the type's name to use as a domain separator.
                static DOMAIN: LazyLock<[u8; 16]> = LazyLock::new(|| {
                    let domain: [u8; 32] = blake3::hash(stringify!($type).as_bytes()).into();
                    domain[..16].try_into().unwrap()
                });

                &*DOMAIN
            }
        }
    };
}

pub(crate) use impl_domain_separator;

impl_domain_separator!(tlsn_core::connection::ServerEphemKey);
impl_domain_separator!(tlsn_core::connection::ConnectionInfo);
impl_domain_separator!(tlsn_core::connection::HandshakeData);
impl_domain_separator!(tlsn_core::transcript::TranscriptCommitment);
impl_domain_separator!(tlsn_core::transcript::TranscriptSecret);
impl_domain_separator!(tlsn_core::transcript::encoding::EncodingCommitment);
impl_domain_separator!(tlsn_core::transcript::hash::PlaintextHash);
