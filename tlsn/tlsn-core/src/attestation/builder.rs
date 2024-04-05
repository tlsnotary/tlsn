use std::collections::HashMap;

use crate::attestation::{AttestationBody, Field, FieldId, FieldKind};

/// An error that can occur when building an attestation.
#[derive(Debug, thiserror::Error)]
#[error("attestation builder error: {0}")]
pub struct AttestationBodyBuilderError(String);

/// A builder for constructing an attestation body.
#[derive(Debug, Default)]
pub struct AttestationBodyBuilder {
    fields: HashMap<FieldId, Field>,
    current_id: u32,
    counts: HashMap<FieldKind, usize>,
}

impl AttestationBodyBuilder {
    fn next_id(&mut self) -> FieldId {
        let id = FieldId(self.current_id);
        self.current_id += 1;
        id
    }

    /// Adds a field to the attestation.
    pub fn field(&mut self, field: Field) -> Result<&mut Self, AttestationBodyBuilderError> {
        let kind = field.kind();
        let count = self.counts.entry(kind).or_default();

        // Only allow one of each of these fields.
        if matches!(
            kind,
            FieldKind::ConnectionInfo
                | FieldKind::HandshakeData
                | FieldKind::CertificateCommitment
                | FieldKind::EncodingCommitment
        ) && *count > 0
        {
            return Err(AttestationBodyBuilderError(format!(
                "only allowed 1 {:?} field",
                kind
            )));
        }

        *count += 1;
        let id = self.next_id();
        self.fields.insert(id, field);

        Ok(self)
    }

    /// Builds the attestation.
    pub fn build(self) -> Result<AttestationBody, AttestationBodyBuilderError> {
        Ok(AttestationBody {
            fields: self.fields,
        })
    }
}
