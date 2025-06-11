use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm, NewAead};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, DecodeFutureTyped,
};
use mpz_vm_core::{prelude::*, Vm};
use rand::RngCore;

use crate::{MpcTlsError, Role};

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

pub(crate) struct AesGcm {
    role: Role,
    key: Option<Array<U8, 16>>,
    iv: Option<Array<U8, 4>>,
    state: State,
}

impl AesGcm {
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

    /// Finishes the decoding of key and IV.
    #[allow(clippy::type_complexity)]
    pub(crate) fn finish_decode(&mut self) -> Result<(), MpcTlsError> {
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

        Ok(())
    }

    pub(crate) fn decrypt(
        &mut self,
        explicit_nonce: Vec<u8>,
        aad: Vec<u8>,
        mut ciphertext: Vec<u8>,
        tag: Vec<u8>,
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

        let mut aes_gcm = Aes128Gcm::new(key.into());

        let mut full_iv = [0u8; 12];
        full_iv[..4].copy_from_slice(iv);
        full_iv[4..12].copy_from_slice(&explicit_nonce);

        aes_gcm
            .decrypt_in_place_detached(
                (&full_iv).into(),
                &aad,
                &mut ciphertext,
                tag.as_slice().into(),
            )
            .map_err(|_| MpcTlsError::record_layer("tag verification failed"))?;

        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm, NewAead};

    #[test]
    fn test_aes_gcm_local() {
        let key = [0u8; 16];
        let iv = [42u8; 4];
        let explicit_nonce = [69u8; 8];
        let aad = [33u8; 13];

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&iv);
        nonce[4..].copy_from_slice(&explicit_nonce);

        let mut aes_gcm_local = AesGcm::new(Role::Leader);
        aes_gcm_local.state = State::Ready {
            key: Some(key),
            iv: Some(iv),
        };

        let mut aes_gcm = Aes128Gcm::new(&key.into());

        let msg = b"hello world";

        let mut ciphertext = msg.to_vec();
        let tag = aes_gcm
            .encrypt_in_place_detached(&nonce.into(), &aad, &mut ciphertext)
            .unwrap();

        let decrypted = aes_gcm_local
            .decrypt(
                explicit_nonce.to_vec(),
                aad.to_vec(),
                ciphertext,
                tag.to_vec(),
            )
            .unwrap();

        assert_eq!(msg, decrypted.as_slice());
    }
}
