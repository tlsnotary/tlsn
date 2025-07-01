//! Plaintext commitment and proof of encryption.

pub(crate) mod hash;
pub(crate) mod transcript;

use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    DecodeFutureTyped, Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Vm, prelude::*};
use tlsn_core::transcript::Record;

use crate::{
    Role,
    zk_aes_ctr::{ZkAesCtr, ZkAesCtrError},
};

/// Commits the plaintext of the provided records, returning a proof of
/// encryption.
///
/// Writes the plaintext VM reference to the provided records.
pub(crate) fn commit_records<'record>(
    vm: &mut dyn Vm<Binary>,
    aes: &mut ZkAesCtr,
    records: impl IntoIterator<Item = &'record Record>,
) -> Result<(Vec<Vector<U8>>, RecordProof), RecordProofError> {
    let mut plaintexts = Vec::new();
    let mut ciphertexts = Vec::new();
    for record in records {
        let (plaintext_ref, ciphertext_ref) = aes
            .encrypt(vm, record.explicit_nonce.clone(), record.ciphertext.len())
            .map_err(ErrorRepr::Aes)?;

        if let Role::Prover = aes.role() {
            let Some(plaintext) = record.plaintext.clone() else {
                return Err(ErrorRepr::MissingPlaintext.into());
            };

            vm.assign(plaintext_ref, plaintext)
                .map_err(RecordProofError::vm)?;
        }
        vm.commit(plaintext_ref).map_err(RecordProofError::vm)?;

        let ciphertext = vm.decode(ciphertext_ref).map_err(RecordProofError::vm)?;

        plaintexts.push(plaintext_ref);
        ciphertexts.push((ciphertext, record.ciphertext.clone()));
    }

    Ok((plaintexts, RecordProof { ciphertexts }))
}

/// Proof of encryption.
#[derive(Debug)]
#[must_use]
#[allow(clippy::type_complexity)]
pub(crate) struct RecordProof {
    ciphertexts: Vec<(DecodeFutureTyped<BitVec, Vec<u8>>, Vec<u8>)>,
}

impl RecordProof {
    /// Verifies the proof.
    pub(crate) fn verify(self) -> Result<(), RecordProofError> {
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
pub(crate) struct RecordProofError(#[from] ErrorRepr);

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
    #[error("ciphertext was not decoded")]
    NotDecoded,
    #[error("ciphertext does not match expected")]
    InvalidCiphertext,
}
