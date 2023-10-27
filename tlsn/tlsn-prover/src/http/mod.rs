//! HTTP Prover.
//!
//! An HTTP prover can be created from a TLS [`Prover`](crate::tls::Prover), after the TLS connection has been closed, by calling the
//! [`to_http`](crate::tls::Prover::to_http) method.
//!
//! The [`HttpProver`] provides higher-level APIs for committing and proving data communicated during an HTTP connection.

pub mod state;

use crate::tls::{state as prover_state, Prover, ProverError};
use tlsn_core::proof::{substring::LabelProof, SubstringProofBuilder};
use tlsn_formats::http::{parse_requests, parse_responses, ParseError};

pub use tlsn_formats::{
    http::{
        HttpCommitmentBuilder, HttpCommitmentBuilderError, HttpProofBuilder, HttpProofBuilderError,
        HttpRequestCommitmentBuilder, HttpResponseCommitmentBuilder, NotarizedHttpSession,
    },
    json::{
        JsonBody, JsonCommitmentBuilder, JsonCommitmentBuilderError, JsonProofBuilder,
        JsonProofBuilderError,
    },
};

/// HTTP prover error.
#[derive(Debug, thiserror::Error)]
pub enum HttpProverError {
    /// An error originated from the TLS prover.
    #[error(transparent)]
    Prover(#[from] ProverError),
    /// Commitment error.
    #[error(transparent)]
    Commitment(#[from] HttpCommitmentBuilderError),
    /// An error occurred while parsing the HTTP data.
    #[error(transparent)]
    Parse(#[from] ParseError),
}

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

    /// Starts verification of the TLS session.
    ///
    /// This function transitions the prover into a state where it can open parts of the
    /// transcript.
    pub fn start_verify(self) -> HttpProver<state::Verify> {
        HttpProver {
            state: state::Verify {
                prover: self.state.prover.start_verify(),
                requests: self.state.requests,
                responses: self.state.responses,
            },
        }
    }
}

impl HttpProver<state::Notarize> {
    /// Generates commitments to the HTTP session prior to finalization.
    pub fn commit(&mut self) -> Result<(), HttpProverError> {
        self.commitment_builder().build()?;

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

impl HttpProver<state::Verify> {
    /// TODO: This needs to be a HttpProofBuilder
    /// which wraps our new alternate SubstringsProofBuilder
    pub fn proof_builder(&self) -> HttpProofBuilder<'_, LabelProof> {
        let prover: Box<dyn SubstringProofBuilder<LabelProof>> =
            Box::new(self.state.prover.proof_builder());
        HttpProofBuilder::new(prover, &self.state.requests, &self.state.responses)
    }

    /// Finalizes the HTTP session.
    // TODO: What to return here?
    pub fn finalize(self) -> Result<(), HttpProverError> {
        todo!()
    }
}
