//! Computes some hashes of the PRF locally.

use crate::{hmac::hmac_sha256, sha256, state_to_bytes, PrfError};
use mpz_core::bitvec::BitVec;
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, DecodeFutureTyped, MemoryExt, ViewExt,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    // The label, e.g. "master secret".
    label: &'static [u8],
    // The start seed and the label, e.g. client_random + server_random + "master_secret".
    start_seed_label: Vec<u8>,
    // The current HMAC message needed for a[i]
    a_msg: Vec<u8>,
    inner_partial: InnerPartial,
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
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::MS_LABEL, outer_partial, inner_partial, 48)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::KEY_LABEL, outer_partial, inner_partial, 40)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::CF_LABEL, outer_partial, inner_partial, 12)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Sha256,
        inner_partial: Sha256,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, Self::SF_LABEL, outer_partial, inner_partial, 12)
    }

    pub(crate) fn wants_flush(&mut self) -> bool {
        let last_p = self.p.last().expect("Prf should be allocated");

        if let State::Done = last_p.state {
            return false;
        }
        true
    }

    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let inner_partial = self.inner_partial.try_recv()?;
        let Some(inner_partial) = inner_partial else {
            return Ok(());
        };

        for (a, p) in self.a.iter_mut().zip(self.p.iter_mut()) {
            match &mut a.state {
                State::Init { .. } => {
                    a.assign_inner_local(vm, inner_partial, &self.a_msg)?;
                    break;
                }
                State::Assigned { output } => {
                    if let Some(output) = output.try_recv().map_err(PrfError::vm)? {
                        let output = output.to_vec();
                        a.state = State::Decoded {
                            output: output.clone(),
                        };
                        self.a_msg = output;
                    }
                }
                _ => (),
            }

            match &mut p.state {
                State::Init { .. } => {
                    if let State::Decoded { output } = &a.state {
                        let mut p_msg = output.to_vec();
                        p_msg.extend_from_slice(&self.start_seed_label);
                        p.assign_inner_local(vm, inner_partial, &p_msg)?;
                    }
                }
                State::Assigned { .. } => {
                    p.state = State::Done;
                }
                _ => (),
            }
        }

        Ok(())
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        let mut start_seed_label = self.label.to_vec();
        start_seed_label.extend_from_slice(&seed);

        self.start_seed_label = start_seed_label.clone();
        self.a_msg = start_seed_label;
    }

    pub(crate) fn output(&self) -> Vec<Array<U8, 32>> {
        self.p.iter().map(|p| p.output).collect()
    }

    fn alloc(
        vm: &mut dyn Vm<Binary>,
        label: &'static [u8],
        outer_partial: Sha256,
        inner_partial: Sha256,
        len: usize,
    ) -> Result<Self, PrfError> {
        let (inner_partial, _) = inner_partial
            .state()
            .expect("state should be set for inner_partial");
        let inner_partial = vm.decode(inner_partial).map_err(PrfError::vm)?;

        let mut prf = Self {
            label,
            start_seed_label: vec![],
            a_msg: vec![],
            inner_partial: InnerPartial::Decoding(inner_partial),
            a: vec![],
            p: vec![],
        };

        assert!(len > 0, "cannot compute 0 bytes for prf");

        let iterations = len / 32 + ((len % 32) != 0) as usize;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial.clone())?;
            prf.a.push(a);

            let p = PHash::alloc(vm, outer_partial.clone())?;
            prf.p.push(p);
        }

        Ok(prf)
    }
}

#[derive(Debug)]
struct PHash {
    output: Array<U8, 32>,
    state: State,
}

impl PHash {
    fn alloc(vm: &mut dyn Vm<Binary>, outer_partial: Sha256) -> Result<Self, PrfError> {
        let inner_local: Array<U8, 32> = vm.alloc().map_err(PrfError::vm)?;
        let output = hmac_sha256(vm, outer_partial, inner_local)?;

        let p_hash = Self {
            state: State::Init { inner_local },
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
            vm.assign(inner_local, state_to_bytes(inner_local_value))
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
        inner_local: Array<U8, 32>,
    },
    Assigned {
        output: DecodeFutureTyped<BitVec, [u8; 32]>,
    },
    Decoded {
        output: Vec<u8>,
    },
    Done,
}

#[derive(Debug)]
enum InnerPartial {
    Decoding(DecodeFutureTyped<BitVec, [u32; 8]>),
    Finished([u32; 8]),
}

impl InnerPartial {
    pub(crate) fn try_recv(&mut self) -> Result<Option<[u32; 8]>, PrfError> {
        match self {
            InnerPartial::Decoding(value) => {
                let value = value.try_recv().map_err(PrfError::vm)?;
                if let Some(value) = value {
                    *self = InnerPartial::Finished(value);
                }
                Ok(value)
            }
            InnerPartial::Finished(value) => Ok(Some(*value)),
        }
    }
}
