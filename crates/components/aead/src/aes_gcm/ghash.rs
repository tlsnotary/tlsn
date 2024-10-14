use crate::{
    aes_gcm::{
        error::{AesGcmError, ErrorKind},
        Aes128, MpcAesGcm,
    },
    config::Role,
    KeystreamBlock,
};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt, ViewExt,
};
use mpz_vm_core::VmExt;
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct GhashPrep {
    pub(crate) role: Role,
    pub(crate) otp: [u8; 16],
    pub(crate) mac_key: Array<U8, 16>,
    pub(crate) j0: VecDeque<KeystreamBlock<Aes128>>,
}

impl GhashPrep {
    pub async fn compute_mac_key<Vm: VmExt<Binary>>(
        &self,
        vm: &mut Vm,
    ) -> Result<[u8; 16], AesGcmError> {
        let mut mac_key = vm
            .decode(self.mac_key)
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?
            .await
            .map_err(|err| AesGcmError::new(ErrorKind::Vm, err))?;

        match self.role {
            Role::Leader => mac_key
                .iter_mut()
                .zip(self.otp)
                .for_each(|(key, otp)| *key ^= otp),
            Role::Follower => mac_key = self.otp,
        }

        Ok(mac_key)
    }

    pub fn compute_j0<Vm>(
        &mut self,
        vm: &mut Vm,
        key: Array<U8, 16>,
        iv: Array<U8, 4>,
        record_count: usize,
    ) -> Result<Vec<KeystreamBlock<Aes128>>, AesGcmError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        if self.j0.len() >= record_count {
            Ok::<_, AesGcmError>(self.j0.drain(..record_count).collect())
        } else {
            let mut keystream: Vec<KeystreamBlock<Aes128>> = self.j0.drain(..).collect();
            for _ in 0..(record_count - keystream.len()) {
                let aes_ctr_block = MpcAesGcm::prepare_keystream(vm, key, iv)?;
                keystream.push(aes_ctr_block);
            }
            Ok(keystream)
        }
    }
}
