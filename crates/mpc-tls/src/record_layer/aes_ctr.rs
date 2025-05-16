use cipher_crate::{KeyIvInit, StreamCipher as _, StreamCipherSeek};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, DecodeFutureTyped,
};
use mpz_vm_core::{prelude::*, Vm};
use rand::RngCore;

use crate::{MpcTlsError, Role};

type LocalAesCtr = ctr::Ctr32BE<aes::Aes128>;

enum State {
    Init,
    Alloc {
        masked_key: Array<U8, 16>,
        masked_iv: Array<U8, 4>,
        key_otp: Option<[u8; 16]>,
        iv_otp: Option<[u8; 4]>,
    },
    Decode {
        masked_key: DecodeFutureTyped<BitVec, [u8; 16]>,
        masked_iv: DecodeFutureTyped<BitVec, [u8; 4]>,
        key_otp: Option<[u8; 16]>,
        iv_otp: Option<[u8; 4]>,
    },
    Ready {
        key: Option<[u8; 16]>,
        iv: Option<[u8; 4]>,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

pub(crate) struct AesCtr {
    role: Role,
    key: Option<Array<U8, 16>>,
    iv: Option<Array<U8, 4>>,
    state: State,
}

impl AesCtr {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            role,
            key: None,
            iv: None,
            state: State::Init,
        }
    }

    pub(crate) fn set_key(&mut self, key: Array<U8, 16>, iv: Array<U8, 4>) {
        self.key = Some(key);
        self.iv = Some(iv);
    }

    pub(crate) fn alloc(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), MpcTlsError> {
        let State::Init = self.state.take() else {
            Err(MpcTlsError::record_layer(
                "aes-ctr must be in initialized state to allocate",
            ))?
        };

        let key = self
            .key
            .ok_or_else(|| MpcTlsError::record_layer("key not set in aes-ctr"))?;
        let iv = self
            .iv
            .ok_or_else(|| MpcTlsError::record_layer("iv not set in aes-ctr"))?;

        let (masked_key, key_otp, masked_iv, iv_otp) = match self.role {
            Role::Leader => {
                let mut key_otp = [0u8; 16];
                rand::rng().fill_bytes(&mut key_otp);
                let mut iv_otp = [0u8; 4];
                rand::rng().fill_bytes(&mut iv_otp);
                let masked_key = vm
                    .mask_private(key, key_otp)
                    .map_err(MpcTlsError::record_layer)?;
                let masked_iv = vm
                    .mask_private(iv, iv_otp)
                    .map_err(MpcTlsError::record_layer)?;
                (masked_key, Some(key_otp), masked_iv, Some(iv_otp))
            }
            Role::Follower => {
                let masked_key = vm.mask_blind(key).map_err(MpcTlsError::record_layer)?;
                let masked_iv = vm.mask_blind(iv).map_err(MpcTlsError::record_layer)?;
                (masked_key, None, masked_iv, None)
            }
        };

        self.state = State::Alloc {
            masked_key,
            masked_iv,
            key_otp,
            iv_otp,
        };

        Ok(())
    }

    pub(crate) fn decode_key(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), MpcTlsError> {
        let State::Alloc {
            masked_key,
            masked_iv,
            key_otp,
            iv_otp,
        } = self.state.take()
        else {
            Err(MpcTlsError::record_layer(
                "aes-ctr must be in allocated state to decode key",
            ))?
        };

        let masked_key = vm.decode(masked_key).map_err(MpcTlsError::record_layer)?;
        let masked_iv = vm.decode(masked_iv).map_err(MpcTlsError::record_layer)?;

        self.state = State::Decode {
            masked_key,
            masked_iv,
            key_otp,
            iv_otp,
        };

        Ok(())
    }

    /// Finishes the decoding of key and IV, returning them.
    pub(crate) fn finish_decode(
        &mut self,
    ) -> Result<(Option<[u8; 16]>, Option<[u8; 4]>), MpcTlsError> {
        let State::Decode {
            mut masked_key,
            mut masked_iv,
            key_otp,
            iv_otp,
        } = self.state.take()
        else {
            Err(MpcTlsError::record_layer(
                "aes-ctr must be in decode state to finish decode",
            ))?
        };

        let (key, iv) = if let Role::Leader = self.role {
            let key_otp = key_otp.expect("leader knows key otp");
            let iv_otp = iv_otp.expect("leader knows iv otp");

            let masked_key = masked_key
                .try_recv()
                .map_err(MpcTlsError::record_layer)?
                .ok_or_else(|| MpcTlsError::record_layer("masked key is not decoded"))?;
            let masked_iv = masked_iv
                .try_recv()
                .map_err(MpcTlsError::record_layer)?
                .ok_or_else(|| MpcTlsError::record_layer("masked iv is not decoded"))?;

            let mut key = masked_key;
            let mut iv = masked_iv;

            key.iter_mut().zip(key_otp).for_each(|(key, otp)| {
                *key ^= otp;
            });

            iv.iter_mut().zip(iv_otp).for_each(|(iv, otp)| {
                *iv ^= otp;
            });

            (Some(key), Some(iv))
        } else {
            (None, None)
        };

        self.state = State::Ready { key, iv };

        Ok((key, iv))
    }

    pub(crate) fn decrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, MpcTlsError> {
        let State::Ready { key, iv, .. } = &self.state else {
            Err(MpcTlsError::record_layer(
                "aes-ctr must be in ready state to decrypt",
            ))?
        };

        if let Role::Follower = self.role {
            return Err(MpcTlsError::record_layer(
                "aes-ctr must be in leader role to decrypt",
            ));
        }

        let key = key.as_ref().expect("leader knows key");
        let iv = iv.as_ref().expect("leader knows iv");

        let explicit_nonce: [u8; 8] =
            explicit_nonce
                .try_into()
                .map_err(|explicit_nonce: Vec<_>| {
                    MpcTlsError::record_layer(format!(
                        "incorrect explicit nonce length: {} != 8",
                        explicit_nonce.len()
                    ))
                })?;

        let mut full_iv = [0u8; 16];
        full_iv[..4].copy_from_slice(iv);
        full_iv[4..12].copy_from_slice(&explicit_nonce);

        let mut aes = LocalAesCtr::new(key.into(), &full_iv.into());

        // Skip the first 32 bytes of the keystream to match the AES-GCM implementation.
        aes.seek(32);

        let mut plaintext = ciphertext;
        aes.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm, NewAead};

    #[test]
    fn test_aes_ctr_local() {
        let key = [0u8; 16];
        let iv = [42u8; 4];
        let explicit_nonce = [69u8; 8];

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&iv);
        nonce[4..].copy_from_slice(&explicit_nonce);

        let mut aes_ctr = AesCtr::new(Role::Leader);
        aes_ctr.state = State::Ready {
            key: Some(key),
            iv: Some(iv),
        };

        let mut aes_gcm = Aes128Gcm::new(&key.into());

        let msg = b"hello world";

        let mut ciphertext = msg.to_vec();
        _ = aes_gcm
            .encrypt_in_place_detached(&nonce.into(), &[], &mut ciphertext)
            .unwrap();

        let decrypted = aes_ctr
            .decrypt(explicit_nonce.to_vec(), ciphertext)
            .unwrap();

        assert_eq!(msg, decrypted.as_slice());
    }
}
