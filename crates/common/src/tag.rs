//! AES-GCM tag commitment.

use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeFutureTyped,
};
use mpz_vm_core::{prelude::*, Vm};

use crate::{transcript::Record, zk_aes_ecb::ZkAesEcb};

/// Commits the encrypted AES-GCM j0 blocks of the given `records`,
/// returning a proof of encryption.
///
/// # Arguments
///
/// * `vm` - Virtual machine.
/// * `key_iv` - Cipher key and IV.
/// * `records` - Records for which the j0 block is committed.
pub fn commit_j0<'record>(
    vm: &mut dyn Vm<Binary>,
    key_iv: (Array<U8, 16>, Array<U8, 4>),
    records: impl Iterator<Item = &'record Record>,
) -> Result<J0Proof, J0ProofError> {
    let mut aes = ZkAesEcb::new();
    aes.set_key(key_iv.0, key_iv.1);

    // Explicit nonce and counter set to 1.
    let nonce_ctr = records
        .into_iter()
        .map(|rec| (rec.explicit_nonce.clone(), 1u32.to_be_bytes().to_vec()))
        .collect::<Vec<_>>();

    aes.alloc(vm, nonce_ctr.len()).map_err(J0ProofError::vm)?;

    let outputs = aes.encrypt(vm, nonce_ctr).map_err(J0ProofError::vm)?;

    let j0s = outputs
        .into_iter()
        .map(|out| vm.decode(out).map_err(J0ProofError::vm))
        .collect::<Result<Vec<_>, J0ProofError>>()?;

    Ok(J0Proof { j0s })
}

/// Proof of encryption of AES-GCM j0 blocks.
#[derive(Debug)]
#[must_use]
pub struct J0Proof {
    /// Futures which will resolve to the value of j0.
    pub j0s: Vec<DecodeFutureTyped<BitVec, [u8; 16]>>,
}

/// Error for [`J0Proof`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct J0ProofError(#[from] ErrorRepr);

impl J0ProofError {
    fn vm<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("j0 proof error: {0}")]
enum ErrorRepr {
    #[error("VM error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
}
