//! TLS record tag verification.

use crate::{ghash::ghash, transcript::Record};
use cipher::{aes::Aes128, Cipher};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeFutureTyped,
};
use mpz_vm_core::{prelude::*, Vm};
use tls_core::cipher::make_tls12_aad;

/// Proves the verification of tags of the given `records`,
/// returning a proof.
///
/// # Arguments
///
/// * `vm` - Virtual machine.
/// * `key_iv` - Cipher key and IV.
/// * `mac_key` - MAC key.
/// * `records` - Records for which the verification is to be proven.
pub fn verify_tags(
    vm: &mut dyn Vm<Binary>,
    key_iv: (Array<U8, 16>, Array<U8, 4>),
    mac_key: Array<U8, 16>,
    records: Vec<Record>,
) -> Result<TagProof, TagProofError> {
    let mut aes = Aes128::default();
    aes.set_key(key_iv.0);
    aes.set_iv(key_iv.1);

    // Compute j0 blocks.
    let j0s = records
        .iter()
        .map(|rec| {
            let block = aes.alloc_ctr_block(vm).map_err(TagProofError::vm)?;

            let explicit_nonce: [u8; 8] =
                rec.explicit_nonce
                    .clone()
                    .try_into()
                    .map_err(|explicit_nonce: Vec<_>| ErrorRepr::ExplicitNonceLength {
                        expected: 8,
                        actual: explicit_nonce.len(),
                    })?;

            vm.assign(block.explicit_nonce, explicit_nonce)
                .map_err(TagProofError::vm)?;
            vm.commit(block.explicit_nonce).map_err(TagProofError::vm)?;

            // j0's counter is set to 1.
            vm.assign(block.counter, 1u32.to_be_bytes())
                .map_err(TagProofError::vm)?;
            vm.commit(block.counter).map_err(TagProofError::vm)?;

            let j0 = vm.decode(block.output).map_err(TagProofError::vm)?;

            Ok(j0)
        })
        .collect::<Result<Vec<_>, TagProofError>>()?;

    let mac_key = vm.decode(mac_key).map_err(TagProofError::vm)?;

    Ok(TagProof {
        j0s,
        records,
        mac_key,
    })
}

/// Proof of tag verification.
#[derive(Debug)]
#[must_use]
pub struct TagProof {
    /// The j0 block for each record.
    j0s: Vec<DecodeFutureTyped<BitVec, [u8; 16]>>,
    records: Vec<Record>,
    /// The MAC key for tag computation.
    mac_key: DecodeFutureTyped<BitVec, [u8; 16]>,
}

impl TagProof {
    /// Verifies the proof.
    pub fn verify(self) -> Result<(), TagProofError> {
        let Self {
            j0s,
            mut mac_key,
            records,
        } = self;

        let mac_key = mac_key
            .try_recv()
            .map_err(TagProofError::vm)?
            .ok_or_else(|| ErrorRepr::NotDecoded)?;

        for (mut j0, rec) in j0s.into_iter().zip(records) {
            let j0 = j0
                .try_recv()
                .map_err(TagProofError::vm)?
                .ok_or_else(|| ErrorRepr::NotDecoded)?;

            let aad = make_tls12_aad(rec.seq, rec.typ, rec.version, rec.ciphertext.len());

            let ghash_tag = ghash(aad.as_ref(), &rec.ciphertext, &mac_key);

            let record_tag = match rec.tag.as_ref() {
                Some(tag) => tag,
                None => {
                    // This will never happen, since we only call this method
                    // for proofs where the records' tags are known.
                    return Err(ErrorRepr::UnknownTag.into());
                }
            };

            if *record_tag
                != ghash_tag
                    .into_iter()
                    .zip(j0.into_iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<_>>()
            {
                return Err(ErrorRepr::InvalidTag.into());
            }
        }

        Ok(())
    }
}

/// Error for [`J0Proof`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TagProofError(#[from] ErrorRepr);

impl TagProofError {
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
    #[error("value was not decoded")]
    NotDecoded,
    #[error("VM error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("tag does not match expected")]
    InvalidTag,
    #[error("tag is not known")]
    UnknownTag,
    #[error("invalid explicit nonce length: expected {expected}, got {actual}")]
    ExplicitNonceLength { expected: usize, actual: usize },
}
