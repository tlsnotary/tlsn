//! Canonical serialization of TLSNotary types.

use crate::{
    attestation::{AttestationHeader, Field, ATTESTATION_ID_LEN, ATTESTATION_VERSION_LEN},
    conn::{
        Certificate, ConnectionInfo, HandshakeData, HandshakeDataV1_2, ServerEphemKey,
        ServerSignature, TlsVersion,
    },
    encoding::EncodingLeaf,
    hash::PlaintextHash,
};

/// Canonical serialization of TLSNotary types.
///
/// This trait is used to serialize types into a canonical byte representation.
///
/// It is critical that the serialization is deterministic and unambiguous.
pub(crate) trait CanonicalSerialize {
    /// Serializes the type into a byte vector.
    fn serialize(&self) -> Vec<u8>;
}

// Make sure to take advantage of destructuring where possible, so if fields are added to a struct
// in the future, the compiler will complain if they aren't included in the serialization.

impl CanonicalSerialize for ConnectionInfo {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let Self {
            time,
            version,
            transcript_length,
        } = self;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&time.to_le_bytes());
        bytes.push(*version as u8);
        bytes.extend_from_slice(&transcript_length.sent.to_le_bytes());
        bytes.extend_from_slice(&transcript_length.received.to_le_bytes());
        bytes
    }
}

impl CanonicalSerialize for HandshakeData {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        match self {
            HandshakeData::V1_2(HandshakeDataV1_2 {
                client_random,
                server_random,
                server_ephemeral_key,
            }) => {
                let mut bytes = Vec::new();
                bytes.push(TlsVersion::V1_2 as u8);
                bytes.extend_from_slice(client_random);
                bytes.extend_from_slice(server_random);
                bytes.extend(CanonicalSerialize::serialize(server_ephemeral_key));
                bytes
            }
        }
    }
}

impl CanonicalSerialize for ServerEphemKey {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let Self { typ, key } = self;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(*typ as u16).to_le_bytes());
        bytes.extend_from_slice(key);
        bytes
    }
}

impl CanonicalSerialize for ServerSignature {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let Self { scheme, sig } = self;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(*scheme as u16).to_le_bytes());
        bytes.extend_from_slice(sig);
        bytes
    }
}

impl CanonicalSerialize for Certificate {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let Self(cert) = self;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(cert.len() as u32).to_le_bytes());
        bytes.extend(cert);
        bytes
    }
}

impl CanonicalSerialize for Field {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.kind() as u8);
        match self {
            Field::ConnectionInfo(info) => {
                bytes.extend(CanonicalSerialize::serialize(info));
            }
            Field::HandshakeData(data) => {
                bytes.extend(CanonicalSerialize::serialize(data));
            }
            Field::CertificateCommitment(commitment) => {
                bytes.extend(CanonicalSerialize::serialize(commitment));
            }
            Field::CertificateChainCommitment(commitment) => {
                bytes.extend(CanonicalSerialize::serialize(commitment));
            }
            Field::EncodingCommitment(commitment) => {
                bytes.extend(CanonicalSerialize::serialize(commitment));
            }
            Field::PlaintextHash(hash) => {
                bytes.extend(CanonicalSerialize::serialize(hash));
            }
            Field::ExtraData(data) => {
                bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                bytes.extend(data);
            }
        }
        bytes
    }
}

impl CanonicalSerialize for AttestationHeader {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let Self { id, version, root } = self;

        let mut bytes = Vec::with_capacity(
            ATTESTATION_ID_LEN + ATTESTATION_VERSION_LEN + root.algorithm().len(),
        );
        bytes.extend_from_slice(&id.0);
        bytes.extend_from_slice(&version.to_le_bytes());
        bytes.extend(CanonicalSerialize::serialize(root));
        bytes
    }
}

impl CanonicalSerialize for EncodingLeaf {
    #[inline]
    fn serialize(&self) -> Vec<u8> {
        let Self { encoding, nonce } = self;

        let mut bytes = encoding.clone();
        bytes.extend_from_slice(nonce);
        bytes
    }
}

impl CanonicalSerialize for PlaintextHash {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(CanonicalSerialize::serialize(&self.hash));
        bytes.extend(CanonicalSerialize::serialize(&self.seq));
        bytes
    }
}
