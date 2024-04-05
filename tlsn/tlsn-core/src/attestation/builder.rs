use std::collections::HashMap;

use crate::attestation::{validation::InvalidAttestationBody, AttestationBody, Field, FieldId};

/// A builder for constructing an attestation body.
#[derive(Debug, Default)]
pub struct AttestationBodyBuilder {
    fields: HashMap<FieldId, Field>,
    current_id: u32,
}

impl AttestationBodyBuilder {
    fn next_field_id(&mut self) -> FieldId {
        let id = FieldId(self.current_id);
        self.current_id += 1;
        id
    }

    /// Adds a field to the attestation.
    pub fn field(&mut self, field: Field) -> &mut Self {
        let id = self.next_field_id();
        self.fields.insert(id, field);
        self
    }

    /// Builds the attestation.
    pub fn build(self) -> Result<AttestationBody, InvalidAttestationBody> {
        AttestationBody::new(self.fields)
    }
}
