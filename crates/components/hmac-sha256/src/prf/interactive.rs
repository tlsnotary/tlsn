use std::sync::Arc;

use crate::{
    convert_to_bytes,
    hmac::HmacSha256,
    prf::merge_outputs,
    sha256::{sha256, Sha256},
    PrfError,
};
use mpz_circuits::{circuits::xor, CircuitBuilder};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};

#[derive(Debug)]
pub(crate) struct PrfFunction {
    label: &'static [u8],
    start_seed_label: Option<Vec<u8>>,
    a: Vec<PHash>,
    p: Vec<PHash>,
}

impl PrfFunction {
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    const MS_LABEL: &[u8] = b"master secret";
    const KEY_LABEL: &[u8] = b"key expansion";
    const CF_LABEL: &[u8] = b"client finished";
    const SF_LABEL: &[u8] = b"server finished";

    pub(crate) fn alloc_master_secret(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::MS_LABEL, 48, 64)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::KEY_LABEL, 40, 64)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::CF_LABEL, 12, 32)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::SF_LABEL, 12, 32)
    }

    pub(crate) fn make_progress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        let a = self.a.first_mut().expect("prf should be allocated");
        let msg = a.msg;

        let msg_value = self
            .start_seed_label
            .clone()
            .expect("seed should be assigned by now");

        vm.mark_public(msg).map_err(PrfError::vm)?;
        vm.assign(msg, msg_value).map_err(PrfError::vm)?;
        vm.commit(msg).map_err(PrfError::vm)?;

        Ok(true)
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
        key: Vector<U8>,
        label: &'static [u8],
        output_len: usize,
        seed_len: usize,
    ) -> Result<Self, PrfError> {
        let mut prf = Self {
            label,
            start_seed_label: None,
            a: vec![],
            p: vec![],
        };

        assert!(
            key.len() <= 64,
            "keys longer than 64 bits are not supported"
        );
        assert!(output_len > 0, "cannot compute 0 bytes for prf");

        let iterations = output_len / 32 + ((output_len % 32) != 0) as usize;

        let outer_partial = Self::compute_outer_partial(vm, key)?;
        let inner_partial = Self::compute_inner_partial(vm, key)?;

        let msg_len_a = label.len() + seed_len;
        let seed_label_ref: Vector<U8> = vm.alloc_vec(msg_len_a).map_err(PrfError::vm)?;
        let mut msg_a = seed_label_ref;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial, inner_partial, msg_a)?;
            msg_a = convert_array(vm, a.output)?.into();
            prf.a.push(a);

            let msg_p = merge_vecs(vm, vec![msg_a, seed_label_ref])?;
            let p = PHash::alloc(vm, outer_partial, inner_partial, msg_p)?;
            prf.p.push(p);
        }

        Ok(prf)
    }

    fn compute_inner_partial(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Array<U32, 8>, PrfError> {
        Self::compute_partial(vm, key, Self::IPAD)
    }

    fn compute_outer_partial(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Array<U32, 8>, PrfError> {
        Self::compute_partial(vm, key, Self::OPAD)
    }

    fn compute_partial(
        vm: &mut dyn Vm<Binary>,
        data: Vector<U8>,
        mask: [u8; 64],
    ) -> Result<Array<U32, 8>, PrfError> {
        let xor = Arc::new(xor(8 * 64));

        let additional_len = 64 - data.len();
        let padding = vec![0_u8; additional_len];

        let padding_ref: Vector<U8> = vm.alloc_vec(additional_len).map_err(PrfError::vm)?;
        vm.mark_public(padding_ref).map_err(PrfError::vm)?;
        vm.assign(padding_ref, padding).map_err(PrfError::vm)?;
        vm.commit(padding_ref).map_err(PrfError::vm)?;

        let mask_ref: Array<U8, 64> = vm.alloc().map_err(PrfError::vm)?;
        vm.mark_public(mask_ref).map_err(PrfError::vm)?;
        vm.assign(mask_ref, mask).map_err(PrfError::vm)?;
        vm.commit(mask_ref).map_err(PrfError::vm)?;

        let xor = Call::builder(xor)
            .arg(data)
            .arg(padding_ref)
            .arg(mask_ref)
            .build()
            .map_err(PrfError::vm)?;
        let key_padded = vm.call(xor).map_err(PrfError::vm)?;

        let mut sha = Sha256::new();
        sha.update(key_padded);
        sha.alloc(vm)
    }
}

#[derive(Debug, Clone)]
struct PHash {
    pub(crate) msg: Vector<U8>,
    pub(crate) output: Array<U32, 8>,
}

impl PHash {
    fn alloc(
        vm: &mut dyn Vm<Binary>,
        outer_partial: Array<U32, 8>,
        inner_partial: Array<U32, 8>,
        msg: Vector<U8>,
    ) -> Result<Self, PrfError> {
        let mut sha = Sha256::new();
        sha.set_state(inner_partial, 64)
            .update(msg)
            .add_padding(vm)?;

        let inner_local = sha.alloc(vm)?;
        let inner_local = convert_array(vm, inner_local)?;

        let hmac = HmacSha256::new(outer_partial, inner_local);
        let output = hmac.alloc(vm).map_err(PrfError::vm)?;

        let p_hash = Self { msg, output };
        Ok(p_hash)
    }
}

fn convert_array(vm: &mut dyn Vm<Binary>, input: Array<U32, 8>) -> Result<Array<U8, 32>, PrfError> {
    let id_circ = {
        let mut builder = CircuitBuilder::new();
        let inputs = (0..32 * 8).map(|_| builder.add_input()).collect::<Vec<_>>();

        for input in inputs.chunks_exact(4 * 8) {
            for byte in input.chunks_exact(8).rev() {
                for &feed in byte.iter() {
                    let output = builder.add_id_gate(feed);
                    builder.add_output(output);
                }
            }
        }

        Arc::new(builder.build().expect("identity circuit is valid"))
    };

    let mut builder = Call::builder(id_circ);
    builder = builder.arg(input);
    let call = builder.build().map_err(PrfError::vm)?;

    vm.call(call).map_err(PrfError::vm)
}

fn merge_vecs(vm: &mut dyn Vm<Binary>, inputs: Vec<Vector<U8>>) -> Result<Vector<U8>, PrfError> {
    let len: usize = inputs.iter().map(|inp| inp.len()).sum();
    let mut builder = CircuitBuilder::new();

    let feeds = (0..len * 8)
        .map(|_| builder.add_input())
        .collect::<Vec<_>>();
    for feed in feeds {
        let output = builder.add_id_gate(feed);
        builder.add_output(output);
    }

    let circuit = builder.build().map_err(PrfError::vm)?;
    let mut builder = Call::builder(Arc::new(circuit));

    for input in inputs {
        builder = builder.arg(input);
    }
    let call = builder.build().map_err(PrfError::vm)?;

    vm.call(call).map_err(PrfError::vm)
}

#[cfg(test)]
mod tests {
    use crate::{
        convert_to_bytes,
        prf::interactive::PrfFunction,
        test_utils::{mock_vm, phash},
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };

    #[tokio::test]
    async fn test_phash_interactive() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let start_seed: Vec<u8> = vec![42; 64];

        let mut label_seed = PrfFunction::MS_LABEL.to_vec();
        label_seed.extend_from_slice(&start_seed);
        let iterations = 2;

        let leader_key: Array<U8, 32> = leader.alloc().unwrap();
        leader.mark_public(leader_key).unwrap();
        leader.assign(leader_key, key).unwrap();
        leader.commit(leader_key).unwrap();

        let mut prf_leader =
            PrfFunction::alloc_master_secret(&mut leader, leader_key.into()).unwrap();
        prf_leader.set_start_seed(start_seed.clone());

        let mut prf_out_leader = vec![];
        for p in prf_leader.output() {
            let p_out = leader.decode(p).unwrap();
            prf_out_leader.push(p_out)
        }

        let follower_key: Array<U8, 32> = follower.alloc().unwrap();
        follower.mark_public(follower_key).unwrap();
        follower.assign(follower_key, key).unwrap();
        follower.commit(follower_key).unwrap();

        let mut prf_follower =
            PrfFunction::alloc_master_secret(&mut follower, follower_key.into()).unwrap();
        prf_follower.set_start_seed(start_seed.clone());

        let mut prf_out_follower = vec![];
        for p in prf_follower.output() {
            let p_out = follower.decode(p).unwrap();
            prf_out_follower.push(p_out)
        }

        loop {
            let leader_finished = prf_leader.make_progress(&mut leader).unwrap();
            let follower_finished = prf_follower.make_progress(&mut follower).unwrap();

            tokio::try_join!(
                leader.execute_all(&mut ctx_a),
                follower.execute_all(&mut ctx_b)
            )
            .unwrap();

            if leader_finished && follower_finished {
                break;
            }
        }

        assert_eq!(prf_out_leader.len(), prf_out_follower.len());

        let prf_result_leader: Vec<u8> = prf_out_leader
            .iter_mut()
            .flat_map(|p| convert_to_bytes(p.try_recv().unwrap().unwrap()))
            .collect();
        let prf_result_follower: Vec<u8> = prf_out_follower
            .iter_mut()
            .flat_map(|p| convert_to_bytes(p.try_recv().unwrap().unwrap()))
            .collect();

        let expected = phash(key.to_vec(), &label_seed, iterations);

        assert_eq!(prf_result_leader, prf_result_follower);
        assert_eq!(prf_result_leader, expected)
    }
}
