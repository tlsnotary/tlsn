use futures::TryFutureExt as _;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeFutureTyped, Vector,
};
use mpz_vm_core::{prelude::*, Vm};
use serde::{Deserialize, Serialize};
use tls_core::msgs::enums::{ContentType, ProtocolVersion};

use crate::{
    record_layer::{
        aead::{AeadError, ComputeTags, MpcAesGcm},
        TagData,
    },
    BoxFut, MpcTlsError,
};

#[allow(clippy::type_complexity)]
fn private(
    vm: &mut dyn Vm<Binary>,
    encrypter: &mut MpcAesGcm,
    op: &EncryptOp,
) -> Result<
    (
        Vector<U8>,
        EncryptOutput,
        BoxFut<Result<Vec<u8>, AeadError>>,
    ),
    MpcTlsError,
> {
    let (plaintext, ciphertext) = encrypter
        .apply_keystream(vm, op.explicit_nonce.clone(), op.len)
        .map_err(MpcTlsError::record_layer)?;

    if let Some(data) = op.plaintext.clone() {
        vm.assign(plaintext, data)
            .map_err(MpcTlsError::record_layer)?;
    }
    vm.commit(plaintext).map_err(MpcTlsError::record_layer)?;

    let ciphertext_fut = Box::pin(
        vm.decode(ciphertext)
            .map_err(MpcTlsError::record_layer)?
            .map_err(AeadError::tag),
    );

    Ok((
        plaintext,
        EncryptOutput::Private(EncryptPrivate {
            ciphertext: vm.decode(ciphertext).map_err(MpcTlsError::record_layer)?,
        }),
        ciphertext_fut,
    ))
}

#[allow(clippy::type_complexity)]
fn public(
    vm: &mut dyn Vm<Binary>,
    encrypter: &mut MpcAesGcm,
    op: &EncryptOp,
) -> Result<(EncryptOutput, BoxFut<Result<Vec<u8>, AeadError>>), MpcTlsError> {
    // Instead of computing the ciphertext in MPC, we only compute the keystream and
    // decode it for both parties. Each party then locally computes the ciphertext.

    let Some(plaintext) = op.plaintext.clone() else {
        return Err(MpcTlsError::record_layer(
            "plaintext must be provided in public mode",
        ));
    };

    let keystream = encrypter
        .take_keystream(vm, op.explicit_nonce.clone(), op.len)
        .map_err(MpcTlsError::record_layer)?;

    let keystream_fut = vm.decode(keystream).map_err(MpcTlsError::record_layer)?;
    let ciphertext_fut = {
        let plaintext = plaintext.clone();
        Box::pin(async move {
            let mut ciphertext = keystream_fut.await.map_err(AeadError::tag)?;
            ciphertext
                .iter_mut()
                .zip(plaintext)
                .for_each(|(a, b)| *a ^= b);

            Ok(ciphertext)
        })
    };

    Ok((
        EncryptOutput::Public(EncryptPublic {
            keystream: vm.decode(keystream).map_err(MpcTlsError::record_layer)?,
            plaintext,
        }),
        ciphertext_fut,
    ))
}

pub(crate) fn encrypt(
    vm: &mut dyn Vm<Binary>,
    encrypter: &mut MpcAesGcm,
    ops: &[EncryptOp],
) -> Result<(Vec<PendingEncrypt>, ComputeTags), MpcTlsError> {
    let mut outputs = Vec::new();
    let mut ciphertext_futs = Vec::new();
    let mut tags_data = Vec::new();
    for op in ops {
        match op.mode {
            EncryptMode::Private => {
                let (plaintext_ref, output, ciphertext_fut) = private(vm, encrypter, op)?;

                outputs.push(PendingEncrypt {
                    plaintext_ref: Some(plaintext_ref),
                    output,
                });
                ciphertext_futs.push(ciphertext_fut);
            }
            EncryptMode::Public => {
                let (output, ciphertext_fut) = public(vm, encrypter, op)?;

                outputs.push(PendingEncrypt {
                    plaintext_ref: None,
                    output,
                });
                ciphertext_futs.push(ciphertext_fut);
            }
        }
        tags_data.push(TagData {
            explicit_nonce: op.explicit_nonce.clone(),
            aad: op.aad.clone(),
        });
    }

    let compute_tags = encrypter
        .compute_tags(vm, ciphertext_futs, tags_data)
        .map_err(MpcTlsError::record_layer)?;

    Ok((outputs, compute_tags))
}

pub(crate) struct EncryptOp {
    pub(crate) seq: u64,
    pub(crate) typ: ContentType,
    pub(crate) version: ProtocolVersion,
    pub(crate) len: usize,
    pub(crate) plaintext: Option<Vec<u8>>,
    pub(crate) explicit_nonce: Vec<u8>,
    pub(crate) aad: Vec<u8>,
    pub(crate) mode: EncryptMode,
}

impl EncryptOp {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        seq: u64,
        typ: ContentType,
        version: ProtocolVersion,
        len: usize,
        plaintext: Option<Vec<u8>>,
        explicit_nonce: Vec<u8>,
        aad: Vec<u8>,
        mode: EncryptMode,
    ) -> Result<Self, MpcTlsError> {
        if let Some(plaintext) = &plaintext {
            if plaintext.len() != len {
                return Err(MpcTlsError::record_layer(format!(
                    "inconsistent plaintext length: {} != {}",
                    plaintext.len(),
                    len
                )));
            }
        }

        if mode == EncryptMode::Public && plaintext.is_none() {
            return Err(MpcTlsError::record_layer(
                "plaintext must be provided in public mode",
            ));
        }

        Ok(Self {
            seq,
            typ,
            version,
            len,
            plaintext,
            explicit_nonce,
            aad,
            mode,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum EncryptMode {
    Private,
    Public,
}

pub(crate) enum EncryptOutput {
    Private(EncryptPrivate),
    Public(EncryptPublic),
}

impl EncryptOutput {
    pub(crate) fn try_encrypt(self) -> Result<Vec<u8>, MpcTlsError> {
        match self {
            EncryptOutput::Private(encrypt) => encrypt.try_encrypt(),
            EncryptOutput::Public(encrypt) => encrypt.try_encrypt(),
        }
    }
}

pub(crate) struct PendingEncrypt {
    pub(crate) plaintext_ref: Option<Vector<U8>>,
    pub(crate) output: EncryptOutput,
}

pub(crate) struct EncryptPrivate {
    ciphertext: DecodeFutureTyped<BitVec, Vec<u8>>,
}

impl EncryptPrivate {
    /// Encrypts the plaintext.
    pub(crate) fn try_encrypt(mut self) -> Result<Vec<u8>, MpcTlsError> {
        let ciphertext = self
            .ciphertext
            .try_recv()
            .map_err(MpcTlsError::record_layer)?
            .ok_or_else(|| MpcTlsError::record_layer("ciphertext is not ready"))?;

        Ok(ciphertext)
    }
}

pub(crate) struct EncryptPublic {
    keystream: DecodeFutureTyped<BitVec, Vec<u8>>,
    plaintext: Vec<u8>,
}

impl EncryptPublic {
    pub(crate) fn try_encrypt(mut self) -> Result<Vec<u8>, MpcTlsError> {
        let keystream = self
            .keystream
            .try_recv()
            .map_err(MpcTlsError::record_layer)?
            .ok_or_else(|| MpcTlsError::record_layer("keystream is not ready"))?;

        if keystream.len() != self.plaintext.len() {
            return Err(MpcTlsError::record_layer(format!(
                "keystream length does not match plaintext length: {} != {}",
                keystream.len(),
                self.plaintext.len()
            )));
        }

        let mut ciphertext = self.plaintext;
        ciphertext
            .iter_mut()
            .zip(keystream)
            .for_each(|(a, b)| *a ^= b);

        Ok(ciphertext)
    }
}
