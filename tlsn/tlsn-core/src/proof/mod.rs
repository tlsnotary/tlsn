//! Different types of proofs used in the TLSNotary protocol.

mod substrings;
mod tls;

pub use substrings::{
    DirectSubstringsProofBuilder, SubstringsProof, SubstringsProofBuilder,
    SubstringsProofBuilderError, SubstringsProofError,
};
pub use tls::{ServerInfo, SessionProof, TlsProof};
