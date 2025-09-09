use std::{future::poll_fn, task::Poll};

pub use tlsn_core::{
    VerifierOutput,
    config::{VerifierConfig, VerifyConfig},
};

use crate::abi;

#[derive(Debug)]
pub struct VerifierError {}

impl std::error::Error for VerifierError {}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifierError")
    }
}

pub mod state {
    use tlsn_core::transcript::TlsTranscript;

    mod sealed {
        pub trait Sealed {}
    }

    pub trait VerifierState: sealed::Sealed {}

    pub struct Initialized {}
    pub struct Setup {}
    pub struct Committed {
        pub(super) tls_transcript: TlsTranscript,
    }

    impl sealed::Sealed for Initialized {}
    impl sealed::Sealed for Setup {}
    impl sealed::Sealed for Committed {}

    impl VerifierState for Initialized {}
    impl VerifierState for Setup {}
    impl VerifierState for Committed {}
}

pub struct Verifier<T: state::VerifierState = state::Initialized> {
    handle: abi::verify::Verifier,
    state: T,
}

impl Verifier {
    pub fn new(config: VerifierConfig) -> Self {
        let config = bincode::serialize(&config).unwrap();

        let handle = abi::verify::Verifier::new(&config);

        Self {
            handle,
            state: state::Initialized {},
        }
    }

    pub async fn setup(self) -> Result<Verifier<state::Setup>, VerifierError> {
        poll_fn(|_| {
            if let abi::verify::SetupReturn::Ready = self.handle.setup() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;

        Ok(Verifier {
            handle: self.handle,
            state: state::Setup {},
        })
    }
}

impl Verifier<state::Setup> {
    pub async fn run(self) -> Result<Verifier<state::Committed>, VerifierError> {
        let res = poll_fn(|_| {
            if let abi::verify::CommitReturn::Ready(res) = self.handle.commit() {
                Poll::Ready(res)
            } else {
                Poll::Pending
            }
        })
        .await;

        res.map(|data| Verifier {
            handle: self.handle,
            state: state::Committed {
                tls_transcript: bincode::deserialize(&data).unwrap(),
            },
        })
        .map_err(|_| todo!())
    }
}

impl Verifier<state::Committed> {
    pub async fn verify(&mut self, config: &VerifyConfig) -> Result<VerifierOutput, VerifierError> {
        let config = bincode::serialize(&config).unwrap();

        self.handle.verify(&config);

        let res = poll_fn(|_| {
            if let abi::verify::VerifyReturn::Ready(res) = self.handle.finish_verify() {
                Poll::Ready(res)
            } else {
                Poll::Pending
            }
        })
        .await;

        res.map(|output| bincode::deserialize(&output).unwrap())
            .map_err(|_| todo!())
    }

    pub async fn close(self) -> Result<(), VerifierError> {
        poll_fn(|_| {
            if let abi::verify::CloseReturn::Ready = self.handle.close() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;

        Ok(())
    }
}
