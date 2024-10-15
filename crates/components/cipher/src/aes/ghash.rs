use crate::{
    aes::{
        error::{AesError, ErrorKind},
        prepare_keystream, Aes128, MpcAes,
    },
    config::Role,
    Keystream,
};
use mpz_memory_core::{
    binary::{Binary, U8},
    Array, MemoryExt, ViewExt,
};
use mpz_vm_core::VmExt;

#[derive(Debug, Clone)]
pub struct GhashPrep {
    pub(crate) role: Role,
    pub(crate) otp: [u8; 16],
    pub(crate) mac_key: Array<U8, 16>,
    pub(crate) j0_blocks: Keystream<Aes128>,
}

impl GhashPrep {
    pub async fn compute_mac_key<Vm: VmExt<Binary>>(
        &self,
        vm: &mut Vm,
    ) -> Result<[u8; 16], AesError> {
        let mut mac_key = vm
            .decode(self.mac_key)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?
            .await
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

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
    ) -> Result<Keystream<Aes128>, AesError>
    where
        Vm: VmExt<Binary> + ViewExt<Binary>,
    {
        if self.j0_blocks.len() >= record_count {
            Ok::<_, AesError>(self.j0_blocks.chunk(record_count))
        } else {
            let mut keystream = std::mem::take(&mut self.j0_blocks);
            let missing = prepare_keystream(vm, key, iv, record_count - keystream.len())?;
            keystream.append(missing);

            Ok(keystream)
        }
    }
}
