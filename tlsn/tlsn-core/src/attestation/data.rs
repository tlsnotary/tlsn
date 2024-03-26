use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{AttestationId, AttestationVersion, FieldId, PrivateField, PublicField},
    Transcript,
};

/// The full data of an attestation, including private fields.
#[derive(Serialize, Deserialize)]
pub struct AttestationData {
    /// An identifier for the attestation.
    pub id: AttestationId,
    /// Version of the attestation.
    pub version: AttestationVersion,
    /// Transcript of data sent from the Prover to the Server.
    pub transcript_tx: Transcript,
    /// Transcript of data received by the Prover from the Server.
    pub transcript_rx: Transcript,
    /// Private fields of the attestation.
    pub private_fields: Vec<PrivateField>,
    /// Public fields of the attestation.
    pub public_fields: HashMap<FieldId, PublicField>,
}

opaque_debug::implement!(AttestationData);
