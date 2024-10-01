use serde::{Deserialize, Serialize};

use crate::{
    connection::{ServerCertOpening, ServerIdentityProof, ServerName},
    index::Index,
    transcript::{
        encoding::EncodingTree, hash::PlaintextHashSecret, Transcript, TranscriptProofBuilder,
    },
};

/// Secret data of an [`Attestation`](crate::attestation::Attestation).
#[derive(Clone, Serialize, Deserialize)]
pub struct Secrets {
    pub(crate) server_name: ServerName,
    pub(crate) server_cert_opening: ServerCertOpening,
    pub(crate) encoding_tree: Option<EncodingTree>,
    pub(crate) plaintext_hashes: Index<PlaintextHashSecret>,
    pub(crate) transcript: Transcript,
}

opaque_debug::implement!(Secrets);

impl Secrets {
    /// Returns the server name.
    pub fn server_name(&self) -> &ServerName {
        &self.server_name
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    /// Returns a server identity proof.
    pub fn identity_proof(&self) -> ServerIdentityProof {
        ServerIdentityProof::new(self.server_name.clone(), self.server_cert_opening.clone())
    }

    /// Returns a transcript proof builder.
    pub fn transcript_proof_builder(&self) -> TranscriptProofBuilder<'_> {
        TranscriptProofBuilder::new(
            &self.transcript,
            self.encoding_tree.as_ref(),
            &self.plaintext_hashes,
        )
    }
}
