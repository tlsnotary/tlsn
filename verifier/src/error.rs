#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
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
    #[error("Error while performing validation check in: {0}")]
    SanityCheckError(String),
    #[error("Failed to verify a Merkle proof")]
    MerkleProofVerificationFailed,
    #[error("Overlapping openings don't match")]
    OverlappingOpeningsDontMatch,
    #[error("Failed while checking committed TLS")]
    CommittedTLSCheckFailed,
    #[error("An internal error occured")]
    InternalError,
    #[error("An internal error during serialization or deserialization")]
    SerializationError,
    #[error("Error during signature verification")]
    SignatureVerificationError,
    #[error("Attempted to create an invalid range")]
    RangeInvalid,
    #[error("Not implemented")]
    NotImplemented,
}
