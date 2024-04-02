use std::collections::HashMap;

use crate::{
    attestation::{
        Attestation, AttestationBody, AttestationHeader, AttestationId, Field, FieldId, FieldKind,
        ATTESTATION_VERSION,
    },
    hash::HashAlgorithm,
};

/// An error that can occur when building an attestation.
#[derive(Debug, thiserror::Error)]
#[error("attestation builder error: {0}")]
pub struct AttestationBuilderError(String);

#[derive(Debug, Default)]
pub struct AttestationBuilder {
    id: Option<AttestationId>,
    fields: HashMap<FieldId, Field>,
    alg: Option<HashAlgorithm>,
    current_id: u32,
    counts: HashMap<FieldKind, usize>,
}

impl AttestationBuilder {
    fn next_id(&mut self) -> FieldId {
        let id = FieldId(self.current_id);
        self.current_id += 1;
        id
    }

    /// Sets the identifier of the attestation.
    pub fn id(&mut self, id: impl Into<AttestationId>) -> &mut Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the hash algorithm of the attestation.
    pub fn hash_algorithm(&mut self, alg: HashAlgorithm) -> &mut Self {
        self.alg = Some(alg);
        self
    }

    /// Adds a field to the attestation.
    pub fn field(&mut self, field: Field) -> Result<&mut Self, AttestationBuilderError> {
        let kind = field.kind();
        let count = self.counts.entry(kind).or_default();

        // Only allow one of each of these fields.
        if matches!(
            kind,
            FieldKind::ConnectionInfo | FieldKind::HandshakeData | FieldKind::EncodingCommitment
        ) && *count > 0
        {
            return Err(AttestationBuilderError(format!(
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
    pub fn build(self) -> Result<Attestation, AttestationBuilderError> {
        let id = self
            .id
            .ok_or_else(|| AttestationBuilderError("must set attestation id".to_string()))?;
        let alg = self
            .alg
            .ok_or_else(|| AttestationBuilderError("must set hash algorithm".to_string()))?;

        let fields = self.fields;

        let body = AttestationBody { fields };
        let root = body.root(alg);
        let header = AttestationHeader {
            id,
            version: ATTESTATION_VERSION.clone(),
            root,
        };

        Ok(Attestation { header, body })
    }
}
