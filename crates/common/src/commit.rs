//! Plaintext commitment and proof of encryption.

use mpz_core::bitvec::BitVec;
use mpz_memory_core::{binary::Binary, DecodeFutureTyped};
use mpz_vm_core::{prelude::*, Vm};

use crate::{
    transcript::Record,
    zk_aes::{ZkAesCtr, ZkAesCtrError},
    Role,
};

/// Commits the plaintext of the provided records, returning a proof of
/// encryption.
///
/// Writes the plaintext VM reference to the provided records.
pub fn commit_records<'record>(
    vm: &mut dyn Vm<Binary>,
    aes: &mut ZkAesCtr,
    records: impl IntoIterator<Item = &'record mut Record>,
) -> Result<RecordProof, RecordProofError> {
    let mut ciphertexts = Vec::new();
    for record in records {
        if record.plaintext_ref.is_some() {
            return Err(ErrorRepr::PlaintextRefAlreadySet.into());
        }

        let (plaintext_ref, ciphertext_ref) = aes
            .encrypt(vm, record.explicit_nonce.clone(), record.ciphertext.len())
            .map_err(ErrorRepr::Aes)?;

        record.plaintext_ref = Some(plaintext_ref);

        if let Role::Prover = aes.role() {
            let Some(plaintext) = record.plaintext.clone() else {
                return Err(ErrorRepr::MissingPlaintext.into());
            };

            vm.assign(plaintext_ref, plaintext)
                .map_err(RecordProofError::vm)?;
        }
        vm.commit(plaintext_ref).map_err(RecordProofError::vm)?;

        let ciphertext = vm.decode(ciphertext_ref).map_err(RecordProofError::vm)?;
        ciphertexts.push((ciphertext, record.ciphertext.clone()));
    }

    Ok(RecordProof { ciphertexts })
}

/// Proof of encryption.
#[derive(Debug)]
#[must_use]
#[allow(clippy::type_complexity)]
pub struct RecordProof {
    ciphertexts: Vec<(DecodeFutureTyped<BitVec, Vec<u8>>, Vec<u8>)>,
}

impl RecordProof {
    /// Verifies the proof.
    pub fn verify(self) -> Result<(), RecordProofError> {
        let Self { ciphertexts } = self;

        for (mut ciphertext, expected) in ciphertexts {
            let ciphertext = ciphertext
                .try_recv()
                .map_err(RecordProofError::vm)?
                .ok_or_else(|| ErrorRepr::NotDecoded)?;

            if ciphertext != expected {
                return Err(ErrorRepr::InvalidCiphertext.into());
            }
        }

        Ok(())
    }
}

/// Error for [`RecordProof`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct RecordProofError(#[from] ErrorRepr);

impl RecordProofError {
    fn vm<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("record proof error: {0}")]
enum ErrorRepr {
    #[error("VM error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("zk aes error: {0}")]
    Aes(ZkAesCtrError),
    #[error("plaintext is missing")]
    MissingPlaintext,
    #[error("plaintext reference is already set")]
    PlaintextRefAlreadySet,
    #[error("ciphertext was not decoded")]
    NotDecoded,
    #[error("ciphertext does not match expected")]
    InvalidCiphertext,
}
