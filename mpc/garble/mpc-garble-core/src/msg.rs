//! Messages used in garbled circuit protocols.

use mpc_core::{commit::Decommitment, hash::Hash};
use serde::{Deserialize, Serialize};

use crate::{
    circuit::EncryptedGate, label_state, Decoding, Delta, EncodedValue, EncodingCommitment,
    EqualityCheck,
};

/// Top-level message type encapsulating all messages used in garbled circuit protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum GarbleMessage {
    ActiveValue(EncodedValue<label_state::Active>),
    ActiveValues(Vec<EncodedValue<label_state::Active>>),
    EncryptedGates(Vec<EncryptedGate>),
    EncodingCommitments(Vec<EncodingCommitment>),
    ValueDecoding(Decoding),
    ValueDecodings(Vec<Decoding>),
    EqualityCheck(EqualityCheck),
    HashCommitment(Hash),
    EqualityCheckOpening(Decommitment<EqualityCheck>),
    EqualityCheckOpenings(Vec<Decommitment<EqualityCheck>>),
    ProofOpenings(Vec<Decommitment<Hash>>),
    Delta(Delta),
    EncoderSeed(Vec<u8>),
}
