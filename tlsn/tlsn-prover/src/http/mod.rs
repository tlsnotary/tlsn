//! HTTP Prover.

#![allow(missing_docs)]
#![allow(unreachable_pub)]

pub mod state;

use tlsn_formats::http::{
    parse_body, parse_requests, parse_responses, Body, HttpCommitmentBuilder, NotarizedHttpSession,
    ParseError,
};

use bytes::Bytes;
use tlsn_core::{Direction, NotarizedSession};
use utils::range::{RangeDifference, RangeSet, RangeUnion};

/// An HTTP prover error.
#[derive(Debug, thiserror::Error)]
pub enum HttpProverError {
    /// An error originated from the TLS prover.
    #[error(transparent)]
    ProverError(#[from] crate::ProverError),
    /// An error occurred while parsing the HTTP data.
    #[error(transparent)]
    ParseError(#[from] ParseError),
}

/// An HTTP prover.
pub struct HttpProver<S: state::State> {
    state: S,
}

impl HttpProver<state::Notarize> {
    pub fn new(prover: crate::Prover<crate::state::Notarize>) -> Result<Self, HttpProverError> {
        let requests = parse_requests(prover.sent_transcript().data().clone())?;
        let responses = parse_responses(prover.recv_transcript().data().clone())?;

        Ok(Self {
            state: state::Notarize {
                prover,
                requests,
                responses,
            },
        })
    }

    pub fn commitment_builder(&mut self) -> HttpCommitmentBuilder {
        HttpCommitmentBuilder::new(
            self.state.prover.commitment_builder(),
            &self.state.requests,
            &self.state.responses,
        )
    }

    pub async fn finalize(self) -> Result<NotarizedHttpSession, HttpProverError> {
        Ok(NotarizedHttpSession::new(
            self.state.prover.finalize().await?,
            self.state.requests,
            self.state.responses,
        ))
    }
}
