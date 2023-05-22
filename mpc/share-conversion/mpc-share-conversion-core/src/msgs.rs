//! Message types used in share conversion protocols

use crate::{Field, Share};

use serde::{Deserialize, Serialize};

/// The messages exchanged between sender and receiver
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum ShareConversionMessage<T: Field> {
    SenderRecordings(SenderRecordings<T>),
}

/// A message containing the sender's seed and the conversion inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct SenderRecordings<T: Field> {
    pub seed: Vec<u8>,
    pub inputs: Vec<Share<T>>,
}
