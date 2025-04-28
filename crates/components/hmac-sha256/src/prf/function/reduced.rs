//! Computes some hashes of the PRF locally.

use crate::{convert_to_bytes, hmac::HmacSha256, sha256::sha256, PrfError};
use mpz_core::bitvec::BitVec;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, DecodeFutureTyped, MemoryExt, ViewExt,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    label: &'static [u8],
    start_seed_label: Option<Vec<u8>>,
    a: Vec<PHash>,
    p: Vec<PHash>,
}

impl PrfFunction {
    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn alloc_master_secret(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::MS_LABEL, outer_partial, inner_partial, 48)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::KEY_LABEL, outer_partial, inner_partial, 40)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::CF_LABEL, outer_partial, inner_partial, 12)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::SF_LABEL, outer_partial, inner_partial, 12)
    }

    pub(crate) fn wants_flush(&mut self) -> bool {
        let last_p = self.p.last().expect("Prf should be allocated");

        if let State::Finished { .. } = last_p.state {
            return false;
        }
        true
    }

    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let mut message = self.start_seed_label.clone();

        for (a, p) in self.a.iter_mut().zip(self.p.iter_mut()) {
            match &mut a.state {
                State::Init { inner_partial, .. } => {
                    if let (Some(msg), Some(inner_partial)) = (
                        message.as_ref(),
                        inner_partial.try_recv().map_err(PrfError::vm)?,
                    ) {
                        a.assign_inner_local(vm, inner_partial, msg)?;
                        message = None;
                    }
                }
                State::Assigned { output } => {
                    if let Some(output) = output.try_recv().map_err(PrfError::vm)? {
                        let output = convert_to_bytes(output).to_vec();
                        a.state = State::Finished {
                            output: output.clone(),
                        };
                        message = Some(output);
                    }
                }
                State::Finished { output } => {
                    message = Some(output.clone());
                }
            }

            match &mut p.state {
                State::Init { inner_partial, .. } => {
                    if let (State::Finished { output }, Some(inner_partial)) =
                        (&a.state, inner_partial.try_recv().map_err(PrfError::vm)?)
                    {
                        let mut msg = output.to_vec();
                        msg.extend_from_slice(
                            self.start_seed_label
                                .as_ref()
                                .expect("Start seed for PRF should be set"),
                        );

                        p.assign_inner_local(vm, inner_partial, &msg)?;
                    }
                }
                State::Assigned { output } => {
                    if let Some(output) = output.try_recv().map_err(PrfError::vm)? {
                        let output = convert_to_bytes(output).to_vec();
                        a.state = State::Finished { output };
                    }
                }
                _ => (),
            }
        }

        Ok(())
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        let mut start_seed_label = self.label.to_vec();
        start_seed_label.extend_from_slice(&seed);

        self.start_seed_label = Some(start_seed_label);
    }

    pub(crate) fn output(&self) -> Vec<Array<U32, 8>> {
        self.p.iter().map(|p| p.output).collect()
    }

    fn alloc(
        vm: &mut dyn Vm<Binary>,
        label: &'static [u8],
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
        len: usize,
    ) -> Result<Self, PrfError> {
        let mut prf = Self {
            label,
            start_seed_label: None,
            a: vec![],
            p: vec![],
        };

        assert!(len > 0, "cannot compute 0 bytes for prf");

        let iterations = len / 32 + ((len % 32) != 0) as usize;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial, inner_partial)?;
            prf.a.push(a);

            let p = PHash::alloc(vm, outer_partial, inner_partial)?;
            prf.p.push(p);
        }

        Ok(prf)
    }
}

#[derive(Debug)]
struct PHash {
    output: Array<U32, 8>,
    state: State,
}

impl PHash {
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
    ) -> Result<Self, PrfError> {
        let inner_local = vm.alloc().map_err(PrfError::vm)?;
        let hmac = HmacSha256::new(outer_partial, inner_local);

        let output = hmac.alloc(vm).map_err(PrfError::vm)?;

        let inner_partial = vm.decode(inner_partial).map_err(PrfError::vm)?;
        let p_hash = Self {
            state: State::Init {
                inner_partial,
                inner_local,
            },
            output,
        };

        Ok(p_hash)
    }

    fn assign_inner_local(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        inner_partial: [u32; 8],
        msg: &[u8],
    ) -> Result<(), PrfError> {
        if let State::Init { inner_local, .. } = self.state {
            let inner_local_value = sha256(inner_partial, 64, msg);

            vm.mark_public(inner_local).map_err(PrfError::vm)?;
            vm.assign(inner_local, convert_to_bytes(inner_local_value))
                .map_err(PrfError::vm)?;
            vm.commit(inner_local).map_err(PrfError::vm)?;

            let output = vm.decode(self.output).map_err(PrfError::vm)?;
            self.state = State::Assigned { output };
        }

        Ok(())
    }
}

#[derive(Debug)]
enum State {
    Init {
        inner_partial: DecodeFutureTyped<BitVec, [u32; 8]>,
        inner_local: Array<U8, 32>,
    },
    Assigned {
        output: DecodeFutureTyped<BitVec, [u32; 8]>,
    },
    Finished {
        output: Vec<u8>,
    },
}
