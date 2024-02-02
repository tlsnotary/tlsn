#[allow(unused_imports)]
pub mod backend;
pub mod error;
pub mod prover;
pub mod state;
use crate::encodings::{FullEncodings, ToFullEncodings};

pub struct VerificationData {
    /// One set corresponds to one commitment.
    pub full_encodings_sets: Vec<FullEncodings>,
    pub init_data: InitData,
}

pub struct InitData(Vec<u8>);
impl InitData {
    pub fn new(init_data: Vec<u8>) -> Self {
        Self(init_data)
    }
}

pub trait ToInitData {
    fn to_init_data(&self) -> InitData;
}

impl ToInitData for &Box<dyn ToInitData> {
    fn to_init_data(&self) -> InitData {
        self.as_ref().to_init_data()
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingVerifierError {
    #[error("Verification failed")]
    VerificationFailed,
}

pub trait EncodingVerifier {
    /// Initializes the verifier with initialization data and prepares it to verify
    /// encodings.
    fn init(&self, init_data: InitData);

    /// Verifies the authenticity of the provided full encodings.
    fn verify(&self, encodings: &FullEncodings) -> Result<(), EncodingVerifierError>;
}
