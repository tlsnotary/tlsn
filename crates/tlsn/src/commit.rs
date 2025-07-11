//! Plaintext commitment and proof of encryption.

pub(crate) mod hash;
pub(crate) mod transcript;

use mpc_tls::SessionKeys;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    DecodeFutureTyped, Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Vm, prelude::*};
use tlsn_core::{
    ProveConfig, ProverOutput,
    transcript::{Record, TlsTranscript, ciphertext::SessionKey},
};

use crate::{
    Role,
    commit::transcript::TranscriptRefs,
    zk_aes_ctr::{ZkAesCtr, ZkAesCtrError},
};

pub(crate) struct CommitmentHelper {
    config: ProveConfig,
    transcript_refs: Option<TranscriptRefs>,
}

impl CommitmentHelper {
    pub(crate) fn new(
        config: ProveConfig,
        keys: SessionKeys,
        server_write_key: SessionKey,
    ) -> Self {
        Self {
            config,
            transcript_refs: None,
        }
    }

    pub(crate) fn commit_records(
        &self,
        vm: &mut dyn Vm<Binary>,
        zk_aes_sent: &mut ZkAesCtr,
        zk_aes_recv: &mut ZkAesCtr,
        transcript: &TlsTranscript,
    ) -> Result<(), RecordProofError> {
        let Some(commit_config) = self.config.transcript_commit() else {
            return Ok(());
        };

        if commit_config.has_ciphertext() {
            todo!();
        }

        if commit_config.has_encoding() {
            todo!();
        }

        if commit_config.has_hash() {
            todo!();
        }

        todo!()
    }

    pub(crate) fn prepare_commitments(&mut self) {
        todo!()
    }

    pub(crate) fn create(self) -> ProverOutput {
        todo!()
    }

    pub(crate) fn transcript_refs(&self) -> Option<&TranscriptRefs> {
        self.transcript_refs.as_ref()
    }
}

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
