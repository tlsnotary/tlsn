use crate::{end_entity_cert, merkle, pubkey, signer};

#[derive(Debug, thiserror::Error, PartialEq)]
#[allow(missing_docs)]
pub enum Error {
    #[error(transparent)]
    EndEntityCertError(#[from] end_entity_cert::EndEntityCertError),
    #[error(transparent)]
    PubKeyError(#[from] pubkey::PubKeyError),
    #[error(transparent)]
    SignerError(#[from] signer::SignerError),
    #[error(transparent)]
    MerkleError(#[from] merkle::MerkleError),
    #[error("SessionHeaderMsg is not expected to contain a signature")]
    SignatureNotExpected,
    #[error("Error while validating a type")]
    ValidationError,
    #[error("Data in overlapping slices don't match")]
    OverlappingSlicesDontMatch,
    #[error("An internal error occured")]
    InternalError,
    #[error("Incorrect Merkle tree indices provided")]
    WrongMerkleTreeIndices,
    #[error("The session header from the Notary is incorrect")]
    WrongSessionHeader,
    #[error("Opening verification failed")]
    OpeningVerificationFailed,
    #[error("Malformed SessionHeaderMsg")]
    MalformedSessionHeaderMsg,
}
