//! HTTP Prover.
//!
//! An HTTP prover can be created from a TLS [`Prover`](crate::tls::Prover), after the TLS connection
//! has been closed, by calling the [`to_http`](crate::tls::Prover::to_http) method.
//!
//! The [`HttpProver`] provides higher-level APIs for committing and proving data communicated during
//! an HTTP connection.

pub mod state;

use tlsn_formats::{
    http::{DefaultHttpCommitter, HttpCommit, HttpCommitError, HttpTranscript},
    ParseError,
};

use crate::tls::{state as prover_state, Prover, ProverError};

pub use tlsn_formats::http::NotarizedHttpSession;

/// HTTP prover error.
#[derive(Debug, thiserror::Error)]
pub enum HttpProverError {
    /// An error originated from the TLS prover.
    #[error(transparent)]
    Prover(#[from] ProverError),
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
        let transcript = HttpTranscript::parse(prover.sent_transcript(), prover.recv_transcript())?;

        Ok(Self {
            state: state::Closed { prover, transcript },
        })
    }

    /// Starts notarization of the HTTP session.
    ///
    /// Used when the TLS verifier is a Notary to transition the prover to the next state
    /// where it can generate commitments to the transcript prior to finalization.
    pub fn start_notarize(self) -> HttpProver<state::Notarize> {
        HttpProver {
            state: state::Notarize {
                prover: self.state.prover.start_notarize(),
                transcript: self.state.transcript,
            },
        }
    }
}

impl HttpProver<state::Notarize> {
    /// Generates commitments to the HTTP session using the provided committer.
    pub fn commit_with<C: HttpCommit>(&mut self, committer: &mut C) -> Result<(), HttpCommitError> {
        committer.commit_transcript(
            self.state.prover.commitment_builder(),
            &self.state.transcript,
        )
    }

    /// Generates commitments to the HTTP session using the default committer.
    pub fn commit(&mut self) -> Result<(), HttpCommitError> {
        DefaultHttpCommitter::default().commit_transcript(
            self.state.prover.commitment_builder(),
            &self.state.transcript,
        )
    }

    /// Finalizes the HTTP session.
    pub async fn finalize(self) -> Result<NotarizedHttpSession, HttpProverError> {
        Ok(NotarizedHttpSession::new(
            self.state.prover.finalize().await?,
            self.state.transcript,
        ))
    }
}
