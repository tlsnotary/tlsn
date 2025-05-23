use mpz_core::bitvec::BitVec;
use mpz_memory_core::{binary::Binary, DecodeFutureTyped};
use mpz_vm_core::{prelude::*, Vm};
use serde::{Deserialize, Serialize};
use tls_core::msgs::enums::{ContentType, ProtocolVersion};
use tlsn_common::ghash::ghash;

use crate::{
    record_layer::{
        aead::{MpcAesGcm, VerifyTags},
        aes_ctr::AesCtr,
        TagData,
    },
    MpcTlsError, Role,
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

use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128,
};

/// Verifies AES-GCM tags locally.
pub(crate) fn verify_tags_locally(
    key: [u8; 16],
    iv: [u8; 4],
    mac_key: [u8; 16],
    ops: &[DecryptOp],
) -> Result<(), MpcTlsError> {
    for DecryptOp {
        ciphertext,
        tag,
        explicit_nonce,
        aad,
        ..
    } in ops
    {
        let aes = Aes128::new_from_slice(&key).expect("key length is 16 bytes");
        let mut j0 = [0; 16];
        j0[0..4].copy_from_slice(&iv);
        j0[4..12].copy_from_slice(explicit_nonce);
        j0[12..16].copy_from_slice(&1u32.to_be_bytes());

        let mut j0 = j0.into();
        aes.encrypt_block(&mut j0);

        debug_assert!({
            // MAC key is an encryption of a zero block.
            let mut zero_block = [0; 16].into();
            aes.encrypt_block(&mut zero_block);
            zero_block == mac_key.into()
        });

        let ghash_tag = ghash(aad, ciphertext, &mac_key);

        if j0
            .iter()
            .zip(ghash_tag)
            .map(|(a, b)| a ^ b)
            .collect::<Vec<_>>()
            != *tag
        {
            return Err(MpcTlsError::record_layer("local tag verification failed"));
        }
    }

    Ok(())
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
    /// The plaintext is private.
    Private,
    /// The plaintext is public.
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

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm, NewAead};
    use cipher_crate::{BlockEncrypt, KeyInit};

    #[test]
    fn test_verify_tags_locally() {
        let key = [0u8; 16];
        let iv = [42u8; 4];
        let explicit_nonce = [69u8; 8];
        let aad = [33u8; 10];
        let msg: &'static [u8; 11] = b"hello world";

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&iv);
        nonce[4..].copy_from_slice(&explicit_nonce);

        let mut aes_gcm = Aes128Gcm::new(&key.into());

        let mut ciphertext = msg.to_vec();
        let expected_tag = aes_gcm
            .encrypt_in_place_detached(&nonce.into(), &aad, &mut ciphertext)
            .unwrap();

        let aes = Aes128::new_from_slice(&key).expect("key length is 16 bytes");
        let mut zero_block = [0; 16].into();
        aes.encrypt_block(&mut zero_block);

        let ops = [DecryptOp {
            aad: aad.to_vec(),
            ciphertext,
            explicit_nonce: explicit_nonce.to_vec(),
            mode: DecryptMode::Private,
            seq: 1,
            tag: expected_tag.to_vec(),
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
        }];

        assert!(verify_tags_locally(key, iv, zero_block.into(), &ops).is_ok());
    }
}
