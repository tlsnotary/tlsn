#[allow(unused_imports)]
//pub mod backend;
pub mod commitment;
pub mod error;
pub mod prover;
pub mod state;
use crate::{
    bitid::IdSet,
    encodings::{ActiveEncodings, FullEncodings},
    InitData,
};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingVerifierError {
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Bad initialization data")]
    BadInitData,
}

pub trait EncodingVerifier<T>
where
    T: IdSet,
{
    /// Initializes the verifier with initialization data and prepares it to verify
    /// encodings.
    fn init(&self, init_data: InitData) -> Result<(), EncodingVerifierError>;

    /// Verifies that the active encodings are authentic.
    /// Upon success returns the corresponding full encodings.
    fn verify(
        &self,
        encodings: ActiveEncodings<T>,
    ) -> Result<FullEncodings<T>, EncodingVerifierError>;
}
