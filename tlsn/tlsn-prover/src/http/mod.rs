//! HTTP Prover.

#![allow(missing_docs)]
#![allow(unreachable_pub)]

pub mod state;

use tlsn_formats::http::{
    parse_requests, parse_responses, HttpCommitmentBuilder, NotarizedHttpSession, ParseError,
};

use crate::{prover_state, Prover};

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

pub struct HttpProverFuture {}

/// An HTTP prover.
pub struct HttpProver<S: state::State> {
    state: S,
}

impl HttpProver<state::Closed> {
    /// Creates a new HTTP prover.
    pub fn new(prover: Prover<prover_state::Closed>) -> Result<Self, HttpProverError> {
        let requests = parse_requests(prover.sent_transcript().data().clone())?;
        let responses = parse_responses(prover.recv_transcript().data().clone())?;

        Ok(Self {
            state: state::Closed {
                prover,
                requests,
                responses,
            },
        })
    }

    /// Starts notarization of the HTTP session.
    ///
    /// If the verifier is a Notary, this function will transition the prover to the next state
    /// where it can generate commitments to the transcript prior to finalization.
    pub fn start_notarize(self) -> HttpProver<state::Notarize> {
        HttpProver {
            state: state::Notarize {
                prover: self.state.prover.start_notarize(),
                requests: self.state.requests,
                responses: self.state.responses,
            },
        }
    }
}

impl HttpProver<state::Notarize> {
    /// Generates commitments to the HTTP session prior to finalization.
    pub fn commit(&mut self) -> Result<(), HttpProverError> {
        self.commitment_builder().build().unwrap();

        Ok(())
    }

    /// Returns a commitment builder for the HTTP session.
    ///
    /// This is for more advanced use cases, you should prefer using `commit` instead.
    pub fn commitment_builder(&mut self) -> HttpCommitmentBuilder {
        HttpCommitmentBuilder::new(
            self.state.prover.commitment_builder(),
            &self.state.requests,
            &self.state.responses,
        )
    }

    /// Finalizes the HTTP session.
    pub async fn finalize(self) -> Result<NotarizedHttpSession, HttpProverError> {
        Ok(NotarizedHttpSession::new(
            self.state.prover.finalize().await?,
            self.state.requests,
            self.state.responses,
        ))
    }
}
