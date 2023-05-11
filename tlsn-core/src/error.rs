#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("An internal error during serialization or deserialization")]
    SerializationError,
    #[error("Attempted to create an invalid range")]
    RangeInvalid,
    #[error("The header is expected to contain a signature")]
    SignatureInHeaderExpected,
    #[error("Can't verify the document because either signature or pubkey were not provided")]
    NoPubkeyOrSignature,
    #[error("The document is expected to contain a signature")]
    SignatureExpected,
    #[error("The document is NOT expected to contain a signature")]
    SignatureNotExpected,
    #[error("x509-parser error: {0}")]
    X509ParserError(String),
    #[error("webpki error: {0}")]
    WebpkiError(String),
    #[error("Certificate chain was empty")]
    EmptyCertificateChain,
    #[error("End entity must not be a certificate authority")]
    EndEntityIsCA,
    #[error("Key exchange data was signed using an unknown curve")]
    UnknownCurveInKeyExchange,
    #[error("Key exchange data was signed using an unknown algorithm")]
    UnknownSigningAlgorithmInKeyExchange,
    #[error("Commitment verification failed")]
    CommitmentVerificationFailed,
    #[error("Error while validating a type")]
    ValidationError,
    #[error("Failed to verify a Merkle proof")]
    MerkleProofVerificationFailed,
    #[error("Data in overlapping slices don't match")]
    OverlappingSlicesDontMatch,
    #[error("Failed while checking committed TLS")]
    CommittedTLSCheckFailed,
    #[error("An internal error occured")]
    InternalError,
    #[error("Error during signature verification")]
    SignatureVerificationError,
    #[error("The types of the signature and the pubkey do not match")]
    SignatureAndPubkeyMismatch,
    #[error("Incorrect Merkle tree indices provided")]
    WrongMerkleTreeIndices,
    #[error("The session header from the Notary is incorrect")]
    WrongSessionHeader,
    #[error("The type of the opening does not match the type of the commitment")]
    CommitmentAndOpeningTypeMismatch,
    #[error("Opening verification failed")]
    OpeningVerificationFailed,
    #[error("Duplicate openings provided")]
    DuplicateOpenings,
}
