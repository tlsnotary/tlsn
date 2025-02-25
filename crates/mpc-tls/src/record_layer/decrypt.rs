use mpz_core::bitvec::BitVec;
use mpz_memory_core::{DecodeFutureTyped, binary::Binary};
use mpz_vm_core::{Vm, prelude::*};
use serde::{Deserialize, Serialize};
use tls_core::msgs::enums::{ContentType, ProtocolVersion};

use crate::{
    MpcTlsError, Role,
    record_layer::{
        TagData,
        aead::{MpcAesGcm, VerifyTags},
        aes_ctr::AesCtr,
    },
};

pub(crate) fn private_mpc(
    vm: &mut dyn Vm<Binary>,
    decrypter: &mut MpcAesGcm,
    otp: Option<&mut Vec<u8>>,
    op: &DecryptOp,
) -> Result<DecryptOutput, MpcTlsError> {
    if let Some(otp) = otp.as_ref() {
        if op.ciphertext.len() > otp.len() {
            return Err(MpcTlsError::record_layer(format!(
                "ciphertext length exceeds allocated: {} > {}",
                op.ciphertext.len(),
                otp.len()
            )));
        }
    }

    let (otp_ref, masked_keystream) = decrypter
        .apply_keystream(vm, op.explicit_nonce.clone(), op.ciphertext.len())
        .map_err(MpcTlsError::record_layer)?;

    let otp = otp.map(|otp| otp.split_off(otp.len() - op.ciphertext.len()));
    if let Some(otp) = otp.clone() {
        vm.assign(otp_ref, otp).map_err(MpcTlsError::record_layer)?;
    }
    vm.commit(otp_ref).map_err(MpcTlsError::record_layer)?;

    // Decode the masked keystream.
    let masked_keystream = vm
        .decode(masked_keystream)
        .map_err(MpcTlsError::record_layer)?;

    Ok(DecryptOutput::Private(DecryptPrivate {
        masked_keystream,
        otp,
        ciphertext: op.ciphertext.clone(),
    }))
}

pub(crate) fn public(
    vm: &mut dyn Vm<Binary>,
    decrypter: &mut MpcAesGcm,
    op: &DecryptOp,
) -> Result<DecryptOutput, MpcTlsError> {
    // Instead of computing the plaintext in MPC, we only compute the keystream and
    // decode it for both parties. Each party then locally computes the plaintext.

    let keystream = decrypter
        .take_keystream(vm, op.explicit_nonce.clone(), op.ciphertext.len())
        .map_err(MpcTlsError::record_layer)?;

    Ok(DecryptOutput::Public(DecryptPublic {
        keystream: vm.decode(keystream).map_err(MpcTlsError::record_layer)?,
        ciphertext: op.ciphertext.clone(),
    }))
}

pub(crate) fn decrypt_mpc(
    vm: &mut dyn Vm<Binary>,
    decrypter: &mut MpcAesGcm,
    mut otp: Option<&mut Vec<u8>>,
    ops: &[DecryptOp],
) -> Result<Vec<PendingDecrypt>, MpcTlsError> {
    let mut pending_decrypt = Vec::with_capacity(ops.len());
    for op in ops {
        match op.mode {
            DecryptMode::Private => {
                pending_decrypt.push(PendingDecrypt {
                    output: private_mpc(vm, decrypter, otp.as_deref_mut(), op)?,
                });
            }
            DecryptMode::Public => {
                pending_decrypt.push(PendingDecrypt {
                    output: public(vm, decrypter, op)?,
                });
            }
        }
    }

    Ok(pending_decrypt)
}

pub(crate) fn decrypt_local(
    role: Role,
    vm: &mut dyn Vm<Binary>,
    mpc_decrypter: &mut MpcAesGcm,
    local_decrypter: &mut AesCtr,
    ops: &[DecryptOp],
) -> Result<Vec<PendingDecrypt>, MpcTlsError> {
    let mut pending_decrypt = Vec::with_capacity(ops.len());
    for op in ops {
        match op.mode {
            DecryptMode::Private => {
                let plaintext = if let Role::Leader = role {
                    let plaintext = local_decrypter
                        .decrypt(op.explicit_nonce.clone(), op.ciphertext.clone())?;
                    Some(plaintext)
                } else {
                    None
                };

                pending_decrypt.push(PendingDecrypt {
                    output: DecryptOutput::Local(DecryptLocal {
                        plaintext: plaintext.clone(),
                    }),
                });
            }
            DecryptMode::Public => {
                pending_decrypt.push(PendingDecrypt {
                    output: public(vm, mpc_decrypter, op)?,
                });
            }
        }
    }

    Ok(pending_decrypt)
}

pub(crate) fn verify_tags(
    vm: &mut dyn Vm<Binary>,
    decrypter: &mut MpcAesGcm,
    ops: &[DecryptOp],
) -> Result<VerifyTags, MpcTlsError> {
    let mut ciphertexts = Vec::with_capacity(ops.len());
    let mut tags = Vec::with_capacity(ops.len());
    let mut tags_data = Vec::with_capacity(ops.len());
    for DecryptOp {
        ciphertext,
        tag,
        explicit_nonce,
        aad,
        ..
    } in ops
    {
        ciphertexts.push(ciphertext.clone());
        tags.push(tag.clone());
        tags_data.push(TagData {
            explicit_nonce: explicit_nonce.clone(),
            aad: aad.clone(),
        });
    }

    decrypter
        .verify_tags(vm, tags_data, ciphertexts, tags)
        .map_err(MpcTlsError::record_layer)
}

pub(crate) struct DecryptOp {
    pub(crate) seq: u64,
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) aad: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) mode: DecryptMode,
}

impl DecryptOp {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        seq: u64,
        typ: ContentType,
        version: ProtocolVersion,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
        tag: Vec<u8>,
        mode: DecryptMode,
    ) -> Self {
        Self {
            seq,
            typ,
            version,
            explicit_nonce,
            ciphertext,
            aad,
            tag,
            mode,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum DecryptMode {
    Private,
    Public,
}

pub(crate) enum DecryptOutput {
    Private(DecryptPrivate),
    Public(DecryptPublic),
    Local(DecryptLocal),
}

impl DecryptOutput {
    pub(crate) fn try_decrypt(self) -> Result<Option<Vec<u8>>, MpcTlsError> {
        match self {
            DecryptOutput::Private(decrypt) => decrypt.try_decrypt(),
            DecryptOutput::Public(decrypt) => decrypt.try_decrypt().map(Some),
            DecryptOutput::Local(decrypt) => decrypt.try_decrypt(),
        }
    }
}

pub(crate) struct PendingDecrypt {
    pub(crate) output: DecryptOutput,
}

pub(crate) struct DecryptPrivate {
    masked_keystream: DecodeFutureTyped<BitVec, Vec<u8>>,
    otp: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
}

impl DecryptPrivate {
    pub(crate) fn try_decrypt(mut self) -> Result<Option<Vec<u8>>, MpcTlsError> {
        let masked_keystream = self
            .masked_keystream
            .try_recv()
            .map_err(MpcTlsError::record_layer)?
            .ok_or_else(|| MpcTlsError::record_layer("masked keystream is not ready"))?;

        let Some(otp) = self.otp else {
            return Ok(None);
        };

        // Recover the plaintext by removing the OTP from the masked keystream and
        // applying the ciphertext.
        let mut plaintext = self.ciphertext;
        plaintext
            .iter_mut()
            .zip(otp)
            .zip(masked_keystream)
            .for_each(|((a, b), c)| *a ^= b ^ c);

        Ok(Some(plaintext))
    }
}

pub(crate) struct DecryptPublic {
    keystream: DecodeFutureTyped<BitVec, Vec<u8>>,
    ciphertext: Vec<u8>,
}

impl DecryptPublic {
    /// Decrypts the ciphertext.
    pub(crate) fn try_decrypt(mut self) -> Result<Vec<u8>, MpcTlsError> {
        let keystream = self
            .keystream
            .try_recv()
            .map_err(MpcTlsError::record_layer)?
            .ok_or_else(|| MpcTlsError::record_layer("keystream is not ready"))?;

        if keystream.len() != self.ciphertext.len() {
            return Err(MpcTlsError::record_layer(format!(
                "keystream length does not match ciphertext: {} != {}",
                keystream.len(),
                self.ciphertext.len()
            )));
        }

        let mut plaintext = self.ciphertext;
        plaintext
            .iter_mut()
            .zip(keystream)
            .for_each(|(a, b)| *a ^= b);

        Ok(plaintext)
    }
}

#[derive(Clone)]
pub(crate) struct DecryptLocal {
    pub(crate) plaintext: Option<Vec<u8>>,
}

impl DecryptLocal {
    pub(crate) fn try_decrypt(self) -> Result<Option<Vec<u8>>, MpcTlsError> {
        Ok(self.plaintext)
    }
}
