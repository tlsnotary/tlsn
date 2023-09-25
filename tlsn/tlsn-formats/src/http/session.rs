use serde::{Deserialize, Serialize};

use tlsn_core::NotarizedSession;

use crate::http::{Body, Request, Response};

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
}
