use crate::{sha256::Sha256, PrfError};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array,
    },
    Vm,
};

#[derive(Debug)]
pub(crate) struct HmacSha256 {
    outer_partial: Array<U32, 8>,
    inner_local: Array<U8, 32>,
}

impl HmacSha256 {
    pub(crate) fn new(outer_partial: Array<U32, 8>, inner_local: Array<U8, 32>) -> Self {
        Self {
            outer_partial,
            inner_local,
        }
    }

    pub(crate) fn alloc(self, vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        let inner_local = self.inner_local.into();

        let mut outer = Sha256::new();
        outer
            .set_state(self.outer_partial, 64)
            .update(inner_local)
            .add_padding(vm)?;

        outer.alloc(vm)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        hmac::HmacSha256,
        sha256::{compress_256, convert_to_bytes, sha256},
    };
    use mpz_common::context::test_st_context;
    use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_vm_core::{
        memory::{
            binary::{U32, U8},
            correlated::Delta,
            Array, MemoryExt, ViewExt,
        },
        Execute,
    };
    use rand::{rngs::StdRng, SeedableRng};

    const SHA256_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[test]
    fn test_hmac_reference() {
        let (inputs, references) = test_fixtures();

        for (input, &reference) in inputs.iter().zip(references.iter()) {
            let outer_partial = compute_outer_partial(input.0.clone());
            let inner_local = compute_inner_local(input.0.clone(), &input.1);

            let hmac = sha256(outer_partial, 64, &convert_to_bytes(inner_local));

            assert_eq!(convert_to_bytes(hmac), reference);
        }
    }

    #[tokio::test]
    async fn test_hmac_circuit() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut generator, mut evaluator) = mock_vm();

        let (inputs, references) = test_fixtures();
        for (input, &reference) in inputs.iter().zip(references.iter()) {
            let outer_partial = compute_outer_partial(input.0.clone());
            let inner_local = compute_inner_local(input.0.clone(), &input.1);

            let outer_partial_ref_gen: Array<U32, 8> = generator.alloc().unwrap();
            generator.mark_public(outer_partial_ref_gen).unwrap();
            generator
                .assign(outer_partial_ref_gen, outer_partial)
                .unwrap();
            generator.commit(outer_partial_ref_gen).unwrap();

            let inner_local_ref_gen: Array<U8, 32> = generator.alloc().unwrap();
            generator.mark_public(inner_local_ref_gen).unwrap();
            generator
                .assign(inner_local_ref_gen, convert_to_bytes(inner_local))
                .unwrap();
            generator.commit(inner_local_ref_gen).unwrap();

            let hmac_gen = HmacSha256::new(outer_partial_ref_gen, inner_local_ref_gen)
                .alloc(&mut generator)
                .unwrap();
            let hmac_gen = generator.decode(hmac_gen).unwrap();

            let outer_partial_ref_ev: Array<U32, 8> = evaluator.alloc().unwrap();
            evaluator.mark_public(outer_partial_ref_ev).unwrap();
            evaluator
                .assign(outer_partial_ref_ev, outer_partial)
                .unwrap();
            evaluator.commit(outer_partial_ref_ev).unwrap();

            let inner_local_ref_ev: Array<U8, 32> = evaluator.alloc().unwrap();
            evaluator.mark_public(inner_local_ref_ev).unwrap();
            evaluator
                .assign(inner_local_ref_ev, convert_to_bytes(inner_local))
                .unwrap();
            evaluator.commit(inner_local_ref_ev).unwrap();

            let hmac_ev = HmacSha256::new(outer_partial_ref_ev, inner_local_ref_ev)
                .alloc(&mut evaluator)
                .unwrap();
            let hmac_ev = evaluator.decode(hmac_ev).unwrap();

            let (hmac_gen, hmac_ev) = tokio::try_join!(
                async {
                    generator.execute_all(&mut ctx_a).await.unwrap();
                    hmac_gen.await
                },
                async {
                    evaluator.execute_all(&mut ctx_b).await.unwrap();
                    hmac_ev.await
                }
            )
            .unwrap();

            assert_eq!(hmac_gen, hmac_ev);
            assert_eq!(convert_to_bytes(hmac_gen), reference);
        }
    }

    fn mock_vm() -> (Garbler<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Garbler::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
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

    #[allow(clippy::type_complexity)]
    fn test_fixtures() -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<[u8; 32]>) {
        let test_vectors: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (
                hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                hex::decode("4869205468657265").unwrap(),
            ),
            (
                hex::decode("4a656665").unwrap(),
                hex::decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f").unwrap(),
            ),
        ];
        let expected: Vec<[u8; 32]> = vec![
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap()
                .try_into()
                .unwrap(),
        ];

        (test_vectors, expected)
    }
}
