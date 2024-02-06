use tlsn_core::{
    proof::{SessionProof, SubstringProve, SubstringsProof, SubstringsProofBuilderError},
    NotarizedSession,
};

use crate::http::HttpTranscript;

/// A notarized HTTP session.
#[derive(Debug)]
pub struct NotarizedHttpSession {
    session: NotarizedSession,
    transcript: HttpTranscript,
}

impl NotarizedHttpSession {
    /// Creates a new notarized HTTP session.
    #[doc(hidden)]
    pub fn new(session: NotarizedSession, transcript: HttpTranscript) -> Self {
        Self {
            session,
            transcript,
        }
    }

    /// Returns the notarized TLS session.
    pub fn session(&self) -> &NotarizedSession {
        &self.session
    }

    /// Returns a proof for the TLS session.
    pub fn session_proof(&self) -> SessionProof {
        self.session.session_proof()
    }

    /// Builds a substring proof with the provided prover.
    pub fn substring_proof<P: SubstringProve<HttpTranscript>>(
        &self,
        prover: &mut P,
    ) -> Result<SubstringsProof, P::Error>
    where
        P::Error: From<SubstringsProofBuilderError>,
    {
        let mut builder = self.session.data().build_substrings_proof();
        prover.prove(&mut builder, &self.transcript)?;
        builder.build().map_err(P::Error::from)
    }
}
