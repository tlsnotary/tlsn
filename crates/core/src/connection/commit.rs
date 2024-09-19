//! Types for committing details of a connection.

use serde::{Deserialize, Serialize};

use crate::{
    connection::ServerCertData,
    hash::{impl_domain_separator, Blinded, HashAlgorithm, HashAlgorithmExt, TypedHash},
};

/// Opens a [`ServerCertCommitment`].
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerCertOpening(Blinded<ServerCertData>);

impl_domain_separator!(ServerCertOpening);

opaque_debug::implement!(ServerCertOpening);

impl ServerCertOpening {
    pub(crate) fn new(data: ServerCertData) -> Self {
        Self(Blinded::new(data))
    }

    pub(crate) fn commit(&self, hasher: &dyn HashAlgorithm) -> ServerCertCommitment {
        ServerCertCommitment(TypedHash {
            alg: hasher.id(),
            value: hasher.hash_separated(self),
        })
    }

    /// Returns the server identity data.
    pub fn data(&self) -> &ServerCertData {
        self.0.data()
    }
}

/// Commitment to a server certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerCertCommitment(pub(crate) TypedHash);

impl_domain_separator!(ServerCertCommitment);
