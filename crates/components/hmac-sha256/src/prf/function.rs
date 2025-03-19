use std::sync::Arc;

use crate::{
    hmac::HmacSha256,
    sha256::{convert_to_bytes, sha256, Sha256},
    PrfError,
};
use mpz_circuits::circuits::xor;
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
        Self::alloc(vm, key, Self::MS_LABEL, 48)
    }

    pub(crate) fn alloc_key_expansion(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::KEY_LABEL, 40)
    }

    pub(crate) fn alloc_client_finished(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::CF_LABEL, 12)
    }

    pub(crate) fn alloc_server_finished(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
    ) -> Result<Self, PrfError> {
        Self::alloc(vm, key, Self::SF_LABEL, 12)
    }

    pub(crate) fn make_progress(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        self.poll_a(vm)?;
        self.poll_p(vm)?;

        let finished = self
            .p
            .last()
            .expect("prf should be allocated")
            .assigned_inner_local;
        Ok(finished)
    }

    pub(crate) fn set_start_seed(&mut self, seed: Vec<u8>) {
        let mut start_seed_label = self.label.to_vec();
        start_seed_label.extend_from_slice(&seed);

        self.start_seed_label = Some(start_seed_label);
    }

    pub(crate) fn output(&self) -> Vec<Array<U32, 8>> {
        self.p.iter().map(|p| p.output).collect()
    }

    fn poll_a(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let Some(mut message) = self.start_seed_label.clone() else {
            return Err(PrfError::state("Starting seed not set for PRF"));
        };

        for a in self.a.iter_mut() {
            let Some(inner_partial) = a.inner_partial_decoded else {
                a.try_recv_inner_partial(vm)?;
                break;
            };

            if !a.assigned_inner_local {
                let inner_local = Self::compute_inner_local(inner_partial, &message);
                a.assign_inner_local(vm, inner_local)?;
                a.assigned_inner_local = true;
            }
            let Some(output) = a.output_decoded else {
                a.try_recv_output(vm)?;
                break;
            };
            message = convert_to_bytes(output).to_vec();
        }

        Ok(())
    }

    fn poll_p(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let Some(start_seed) = self.start_seed_label.clone() else {
            return Err(PrfError::state("Starting seed not set for PRF"));
        };

        for (i, p) in self.p.iter_mut().enumerate() {
            let Some(message) = self.a[i].output_decoded else {
                break;
            };
            let mut message = convert_to_bytes(message).to_vec();
            message.extend_from_slice(&start_seed);

            let Some(inner_partial) = p.inner_partial_decoded else {
                p.try_recv_inner_partial(vm)?;
                break;
            };

            if !p.assigned_inner_local {
                let inner_local = Self::compute_inner_local(inner_partial, &message);
                p.assign_inner_local(vm, inner_local)?;
                p.assigned_inner_local = true;
            }
        }

        Ok(())
    }

    fn alloc(
        vm: &mut dyn Vm<Binary>,
        key: Vector<U8>,
        label: &'static [u8],
        len: usize,
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
        assert!(len > 0, "cannot compute 0 bytes for prf");

        let iterations = len / 32 + ((len % 32) != 0) as usize;

        let outer_partial = Self::compute_outer_partial(vm, key)?;
        let inner_partial = Self::compute_inner_partial(vm, key)?;

        for _ in 0..iterations {
            let a = PHash::alloc(vm, outer_partial, inner_partial)?;
            prf.a.push(a);

            let p = PHash::alloc(vm, outer_partial, inner_partial)?;
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

    fn compute_inner_local(inner_partial: [u32; 8], message: &[u8]) -> [u32; 8] {
        sha256(inner_partial, 64, message)
    }
}

#[derive(Debug, Clone)]
struct PHash {
    pub(crate) outer_partial: Array<U32, 8>,
    pub(crate) inner_partial: Array<U32, 8>,
    pub(crate) inner_partial_decoded: Option<[u32; 8]>,
    pub(crate) inner_local: Array<U8, 32>,
    pub(crate) assigned_inner_local: bool,
    pub(crate) output: Array<U32, 8>,
    pub(crate) output_decoded: Option<[u32; 8]>,
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

        let p_hash = Self {
            outer_partial,
            inner_partial,
            inner_partial_decoded: None,
            inner_local,
            assigned_inner_local: false,
            output,
            output_decoded: None,
        };

        Ok(p_hash)
    }

    fn try_recv_inner_partial(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let mut inner_partial_decoded = vm.decode(self.inner_partial).map_err(PrfError::vm)?;
        self.inner_partial_decoded = inner_partial_decoded.try_recv().map_err(PrfError::vm)?;
        Ok(())
    }

    fn try_recv_output(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let mut output_decoded = vm.decode(self.output).map_err(PrfError::vm)?;
        self.output_decoded = output_decoded.try_recv().map_err(PrfError::vm)?;
        Ok(())
    }

    fn assign_inner_local(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        inner_local: [u32; 8],
    ) -> Result<(), PrfError> {
        let inner_local_ref: Array<U8, 32> = self.inner_local;

        vm.mark_public(inner_local_ref).map_err(PrfError::vm)?;
        vm.assign(inner_local_ref, convert_to_bytes(inner_local))
            .map_err(PrfError::vm)?;
        vm.commit(inner_local_ref).map_err(PrfError::vm)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mpz_common::context::test_st_context;
    use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_vm_core::{
        memory::{binary::U8, correlated::Delta, Array, MemoryExt, ViewExt},
        Execute,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        prf::function::PrfFunction,
        sha256::{compress_256, convert_to_bytes, sha256},
    };

    const SHA256_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[tokio::test]
    async fn test_prf() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut generator, mut evaluator) = mock_vm();

        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let start_seed: Vec<u8> = vec![42; 12];

        let mut label_seed = PrfFunction::MS_LABEL.to_vec();
        label_seed.extend_from_slice(&start_seed);
        let iterations = 2;

        let key_ref_gen: Array<U8, 32> = generator.alloc().unwrap();
        generator.mark_public(key_ref_gen).unwrap();
        generator.assign(key_ref_gen, key).unwrap();
        generator.commit(key_ref_gen).unwrap();

        let mut prf_gen =
            PrfFunction::alloc_master_secret(&mut generator, key_ref_gen.into()).unwrap();
        prf_gen.set_start_seed(start_seed.clone());

        let mut prf_out_gen = vec![];
        for p in prf_gen.output() {
            let p_out = generator.decode(p).unwrap();
            prf_out_gen.push(p_out)
        }

        let key_ref_ev: Array<U8, 32> = evaluator.alloc().unwrap();
        evaluator.mark_public(key_ref_ev).unwrap();
        evaluator.assign(key_ref_ev, key).unwrap();
        evaluator.commit(key_ref_ev).unwrap();

        let mut prf_ev =
            PrfFunction::alloc_master_secret(&mut evaluator, key_ref_ev.into()).unwrap();
        prf_ev.set_start_seed(start_seed.clone());

        let mut prf_out_ev = vec![];
        for p in prf_ev.output() {
            let p_out = evaluator.decode(p).unwrap();
            prf_out_ev.push(p_out)
        }

        loop {
            let gen_finished = prf_gen.make_progress(&mut generator).unwrap();
            let ev_finished = prf_ev.make_progress(&mut evaluator).unwrap();

            tokio::try_join!(
                generator.execute_all(&mut ctx_a),
                evaluator.execute_all(&mut ctx_b)
            )
            .unwrap();

            if gen_finished && ev_finished {
                break;
            }
        }

        assert_eq!(prf_out_gen.len(), prf_out_ev.len());

        let prf_result_gen: Vec<u8> = prf_out_gen
            .iter_mut()
            .flat_map(|p| convert_to_bytes(p.try_recv().unwrap().unwrap()))
            .collect();
        let prf_result_ev: Vec<u8> = prf_out_ev
            .iter_mut()
            .flat_map(|p| convert_to_bytes(p.try_recv().unwrap().unwrap()))
            .collect();

        let expected = prf_reference(key.to_vec(), &label_seed, iterations);

        assert_eq!(prf_result_gen, prf_result_ev);
        assert_eq!(prf_result_gen, expected)
    }

    fn mock_vm() -> (Garbler<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Garbler::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }

    fn prf_reference(key: Vec<u8>, seed: &[u8], iterations: usize) -> Vec<u8> {
        // A() is defined as:
        //
        // A(0) = seed
        // A(i) = HMAC_hash(secret, A(i-1))
        let mut a_cache: Vec<_> = Vec::with_capacity(iterations + 1);
        a_cache.push(seed.to_vec());

        for i in 0..iterations {
            let a_i = hmac_sha256(key.clone(), &a_cache[i]);
            a_cache.push(a_i.to_vec());
        }

        // HMAC_hash(secret, A(i) + seed)
        let mut output: Vec<_> = Vec::with_capacity(iterations * 32);
        for i in 0..iterations {
            let mut a_i_seed = a_cache[i + 1].clone();
            a_i_seed.extend_from_slice(seed);

            let hash = hmac_sha256(key.clone(), &a_i_seed);
            output.extend_from_slice(&hash);
        }

        output
    }

    fn hmac_sha256(key: Vec<u8>, msg: &[u8]) -> [u8; 32] {
        let outer_partial = compute_outer_partial(key.clone());
        let inner_local = compute_inner_local(key, msg);

        let hmac = sha256(outer_partial, 64, &convert_to_bytes(inner_local));
        convert_to_bytes(hmac)
    }

    fn compute_outer_partial(mut key: Vec<u8>) -> [u32; 8] {
        assert!(key.len() <= 64);

        key.resize(64, 0_u8);
        let key_padded: [u8; 64] = key
            .into_iter()
            .map(|b| b ^ 0x5c)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        compress_256(SHA256_IV, &key_padded)
    }

    fn compute_inner_local(mut key: Vec<u8>, msg: &[u8]) -> [u32; 8] {
        assert!(key.len() <= 64);

        key.resize(64, 0_u8);
        let key_padded: [u8; 64] = key
            .into_iter()
            .map(|b| b ^ 0x36)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        let state = compress_256(SHA256_IV, &key_padded);
        sha256(state, 64, msg)
    }
}
