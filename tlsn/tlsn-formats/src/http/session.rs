use tlsn_core::{proof::SessionProof, NotarizedSession};

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

    /// Returns the HTTP transcript.
    pub fn transcript(&self) -> &HttpTranscript {
        &self.transcript
    }

    /// Returns a proof for the TLS session.
    pub fn session_proof(&self) -> SessionProof {
        self.session.session_proof()
    }
}
