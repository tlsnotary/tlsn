#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("Can't verify the document because either signature or pubkey were not provided")]
    NoPubkeyOrSignature,
    #[error("x509-parser error: {0}")]
    X509ParserError(String),
    #[error("webpki error: {0}")]
    WebpkiError(String),
    #[error("unspecified error")]
    VerificationError,
    #[error("the certificate chain was empty")]
    EmptyCertificateChain,
    #[error("the end entity must not be a certificate authority")]
    EndEntityIsCA,
    #[error("the key exchange was signed using an unknown curve")]
    UnknownCurveInKeyExchange,
    #[error("the key exchange was signed using an unknown algorithm")]
    UnknownSigningAlgorithmInKeyExchange,
    #[error("Commitment verification failed")]
    CommitmentVerificationFailed,
    #[error("error while performing sanity check")]
    SanityCheckError,
    #[error("Failed to verify a Merkle proof")]
    MerkleProofVerificationFailed,
    #[error("Overlapping openings don't match")]
    OverlappingOpeningsDontMatch,
    #[error("internal error occured")]
    InternalError,
}
