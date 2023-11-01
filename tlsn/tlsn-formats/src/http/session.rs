use serde::{Deserialize, Serialize};

use tlsn_core::{proof::SessionProof, NotarizedSession};

use crate::http::{Body, Request, Response};

use super::HttpProofBuilder;

/// A notarized HTTP session.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotarizedHttpSession {
    session: NotarizedSession,
    requests: Vec<(Request, Option<Body>)>,
    responses: Vec<(Response, Option<Body>)>,
}

impl NotarizedHttpSession {
    /// Creates a new notarized HTTP session.
    #[doc(hidden)]
    pub fn new(
        session: NotarizedSession,
        requests: Vec<(Request, Option<Body>)>,
        responses: Vec<(Response, Option<Body>)>,
    ) -> Self {
        Self {
            session,
            requests,
            responses,
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

    /// Returns a proof builder for the HTTP session.
    pub fn proof_builder(&self) -> HttpProofBuilder {
        HttpProofBuilder::new(
            self.session.data().build_substrings_proof(),
            self.session.data().commitments(),
            &self.requests,
            &self.responses,
        )
    }
}
