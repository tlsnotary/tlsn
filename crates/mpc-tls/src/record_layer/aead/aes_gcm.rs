use std::{future::Future, sync::Arc};

use cipher::{aes::Aes128, Cipher, CtrBlock, Keystream};
use mpz_common::{Context, Flush};
use mpz_core::bitvec::BitVec;
use mpz_fields::gf2_128::Gf2_128;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeFutureTyped, Vector,
};
use mpz_share_conversion::ShareConvert;
use mpz_vm_core::{prelude::*, Vm};
use tracing::instrument;

use crate::{
    decode::OneTimePadShared,
    record_layer::{
        aead::{
            ghash::{ComputeTagData, ComputeTags, Ghash, MpcGhash, VerifyTagData, VerifyTags},
            AeadError, Block, Ctr, Nonce,
        },
        TagData,
    },
    Role,
};

const START_CTR: u32 = 2;

#[allow(clippy::type_complexity)]
enum State {
    Init {
        ghash: Box<dyn Ghash + Send + Sync>,
    },
    Setup {
        input: Vector<U8>,
        keystream: Keystream<Nonce, Ctr, Block>,
        j0s: Vec<(CtrBlock<Nonce, Ctr, Block>, OneTimePadShared<[u8; 16]>)>,
        ghash_key_share: OneTimePadShared<[u8; 16]>,
        ghash: Box<dyn Ghash + Send + Sync>,
        ghash_key: Array<U8, 16>,
    },
    Ready {
        input: Vector<U8>,
        keystream: Keystream<Nonce, Ctr, Block>,
        j0s: Vec<(CtrBlock<Nonce, Ctr, Block>, OneTimePadShared<[u8; 16]>)>,
        ghash: Arc<dyn Ghash + Send + Sync>,
        ghash_key: Array<U8, 16>,
    },
    Complete {},
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

pub(crate) struct MpcAesGcm {
    role: Role,
    aes: Aes128,
    state: State,
}

impl MpcAesGcm {
    /// Creates a new AES-GCM instance.
    pub(crate) fn new<C>(converter: C, role: Role) -> Self
    where
        C: ShareConvert<Gf2_128> + Flush + Send + Sync + 'static,
    {
        Self {
            role,
            aes: Aes128::default(),
            state: State::Init {
                ghash: Box::new(MpcGhash::new(converter)),
            },
        }
    }

    /// Allocates resources.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine to allocate in.
    /// * `records` - Number of records to allocate.
    /// * `len` - Length of the input text in bytes.
    pub(crate) fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        records: usize,
        len: usize,
    ) -> Result<(), AeadError> {
        let State::Init { mut ghash } = self.state.take() else {
            return Err(AeadError::state("must be in init state to allocate"));
        };

        let zero_block: Array<U8, 16> = vm.alloc()?;
        vm.mark_public(zero_block)?;
        vm.assign(zero_block, [0u8; 16])?;
        vm.commit(zero_block)?;

        ghash.alloc()?;
        let ghash_key = self.aes.alloc_block(vm, zero_block)?;
        let ghash_key_share = OneTimePadShared::<[u8; 16]>::new(self.role, ghash_key, vm)?;

        // Allocate J0 secret sharing for GHASH.
        let mut j0s = Vec::with_capacity(records);
        for _ in 0..records {
            let j0 = self.aes.alloc_ctr_block(vm)?;
            let j0_shared = OneTimePadShared::<[u8; 16]>::new(self.role, j0.output, vm)?;

            j0s.push((j0, j0_shared));
        }

        // Allocate encryption/decryption.

        // Round up the length to the nearest multiple of the block size.
        let len = 16 * len.div_ceil(16);

        let input = vm.alloc_vec::<U8>(len)?;
        match self.role {
            Role::Leader => {
                vm.mark_private(input)?;
            }
            Role::Follower => {
                vm.mark_blind(input)?;
            }
        }

        let keystream = self.aes.alloc_keystream(vm, len)?;

        self.state = State::Setup {
            input,
            keystream,
            j0s,
            ghash,
            ghash_key_share,
            ghash_key,
        };

        Ok(())
    }

    pub(crate) async fn preprocess(&mut self, ctx: &mut Context) -> Result<(), AeadError> {
        let State::Setup { ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in setup state to preprocess"));
        };

        ghash.preprocess(ctx).await?;

        Ok(())
    }

    pub(crate) fn set_key(&mut self, key: Array<U8, 16>) {
        self.aes.set_key(key);
    }

    pub(crate) fn set_iv(&mut self, iv: Array<U8, 4>) {
        self.aes.set_iv(iv);
    }

    pub(crate) async fn setup(&mut self, ctx: &mut Context) -> Result<(), AeadError> {
        let State::Setup {
            input,
            keystream,
            j0s,
            ghash_key_share,
            mut ghash,
            ghash_key,
        } = self.state.take()
        else {
            return Err(AeadError::state("must be in setup state to set up"));
        };

        let key = ghash_key_share.await.map_err(AeadError::tag)?;
        ghash.set_key(key.to_vec())?;
        ghash.setup(ctx).await?;

        self.state = State::Ready {
            input,
            keystream,
            j0s,
            ghash: Arc::from(ghash),
            ghash_key,
        };

        Ok(())
    }

    /// Returns `len` bytes of input and output text.
    ///
    /// The outer context is responsible for assigning to the input text.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `len` - Number of bytes to take.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn apply_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: Vec<u8>,
        len: usize,
    ) -> Result<(Vector<U8>, Vector<U8>), AeadError> {
        let State::Ready {
            input, keystream, ..
        } = &mut self.state
        else {
            return Err(AeadError::state(
                "must be in ready state to apply keystream",
            ));
        };

        let explicit_nonce: [u8; 8] = explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
            AeadError::cipher(format!(
                "explicit nonce length: expected {}, got {}",
                8,
                nonce.len()
            ))
        })?;

        let block_count = len.div_ceil(16);
        let padded_len = block_count * 16;
        let padding_len = padded_len - len;

        if padded_len > input.len() {
            return Err(AeadError::cipher(format!(
                "input length exceeds allocated: {} > {}",
                padded_len,
                input.len()
            )));
        }

        let mut input = input.split_off(input.len() - padded_len);
        let keystream = keystream.consume(padded_len)?;
        let mut output = keystream.apply(vm, input)?;

        // Assign counter block inputs.
        let mut ctr = START_CTR..;
        keystream.assign(vm, explicit_nonce, move || {
            ctr.next().expect("range is unbounded").to_be_bytes()
        })?;

        // Assign zeroes to the padding.
        if padding_len > 0 {
            let padding = input.split_off(input.len() - padding_len);
            // To simplify the impl, we don't mark the padding as public, that's why only
            // the prover assigns it.
            if let Role::Leader = self.role {
                vm.assign(padding, vec![0; padding_len])?;
            }
            vm.commit(padding)?;
            output.truncate(len);
        }

        Ok((input, output))
    }

    /// Returns `len` bytes of keystream.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `len` - Number of bytes to take.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn take_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        explicit_nonce: Vec<u8>,
        len: usize,
    ) -> Result<Vector<U8>, AeadError> {
        let State::Ready {
            input, keystream, ..
        } = &mut self.state
        else {
            return Err(AeadError::state("must be in ready state to take keystream"));
        };

        let explicit_nonce: [u8; 8] = explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
            AeadError::cipher(format!(
                "explicit nonce length: expected {}, got {}",
                8,
                nonce.len()
            ))
        })?;

        let block_count = len.div_ceil(16);
        let padded_len = block_count * 16;

        if padded_len > input.len() {
            return Err(AeadError::cipher(format!(
                "input length exceeds allocated: {} > {}",
                padded_len,
                input.len()
            )));
        }

        let keystream = keystream.consume(len)?;

        // Assign counter block inputs.
        let mut ctr = START_CTR..;
        keystream.assign(vm, explicit_nonce, move || {
            ctr.next().expect("range is unbounded").to_be_bytes()
        })?;

        Ok(keystream.to_vector(vm, len)?)
    }

    /// Decodes the server write MAC key, returning it.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn decode_mac_key(
        &mut self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<DecodeFutureTyped<BitVec, [u8; 16]>, AeadError> {
        let State::Ready { ghash_key, .. } = &self.state else {
            return Err(AeadError::state("must be in ready state to decode mac key"));
        };

        let fut = vm.decode(*ghash_key)?;

        self.state = State::Complete {};

        Ok(fut)
    }

    /// Computes tags for the provided ciphertext. See
    /// [`verify_tags`](MpcAesGcm::verify_tags) for a method that verifies an
    /// tags instead.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `explicit_nonce` - Explicit nonce.
    /// * `ciphertext` - Ciphertext to compute the tag for.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) fn compute_tags<C>(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        ciphertexts: Vec<C>,
        data: Vec<TagData>,
    ) -> Result<ComputeTags, AeadError>
    where
        C: Future<Output = Result<Vec<u8>, AeadError>> + Send + Sync + 'static,
    {
        let State::Ready { j0s, ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in ready state to compute tags"));
        };

        if ciphertexts.len() != data.len() {
            return Err(AeadError::tag("ciphertext and data length mismatch"));
        } else if ciphertexts.len() > j0s.len() {
            return Err(AeadError::tag("ciphertext length exceeds allocated"));
        }

        let mut tag_data = Vec::with_capacity(ciphertexts.len());
        for (ciphertext, data) in ciphertexts.into_iter().zip(data) {
            let explicit_nonce: [u8; 8] =
                data.explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
                    AeadError::cipher(format!(
                        "explicit nonce length: expected {}, got {}",
                        8,
                        nonce.len()
                    ))
                })?;
            let (j0, j0_shared) = j0s.pop().expect("j0 length was checked");

            assign_j0(vm, j0, explicit_nonce)?;

            tag_data.push(ComputeTagData {
                j0: j0_shared,
                ciphertext: Box::pin(ciphertext),
                aad: data.aad,
            });
        }

        let tags = ComputeTags::new(self.role, tag_data, ghash.clone());

        Ok(tags)
    }

    /// Verifies the tags for the provided ciphertexts.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `data` - Tag data associated with `tags`.
    /// * `ciphertexts` - Ciphertexts to verify the tags for.
    /// * `tags` - Tags to verify.
    pub(crate) fn verify_tags(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        data: Vec<TagData>,
        ciphertexts: Vec<Vec<u8>>,
        tags: Vec<Vec<u8>>,
    ) -> Result<VerifyTags, AeadError> {
        let State::Ready { j0s, ghash, .. } = &mut self.state else {
            return Err(AeadError::state("must be in ready state to verify tags"));
        };

        if ciphertexts.len() != data.len() {
            return Err(AeadError::tag("ciphertext and data length mismatch"));
        } else if ciphertexts.len() != tags.len() {
            return Err(AeadError::tag("ciphertext and tag length mismatch"));
        } else if ciphertexts.len() > j0s.len() {
            return Err(AeadError::tag("ciphertext length exceeds allocated"));
        }

        let mut tag_data = Vec::with_capacity(ciphertexts.len());
        for ((ciphertext, data), tag) in ciphertexts.into_iter().zip(data).zip(tags) {
            let explicit_nonce: [u8; 8] =
                data.explicit_nonce.try_into().map_err(|nonce: Vec<_>| {
                    AeadError::cipher(format!(
                        "explicit nonce length: expected {}, got {}",
                        8,
                        nonce.len()
                    ))
                })?;
            let (j0, j0_shared) = j0s.pop().expect("j0 length was checked");

            assign_j0(vm, j0, explicit_nonce)?;

            tag_data.push(VerifyTagData {
                j0: j0_shared,
                ciphertext,
                aad: data.aad,
                tag,
            });
        }

        let tags = VerifyTags::new(self.role, tag_data, ghash.clone());

        Ok(tags)
    }
}

fn assign_j0(
    vm: &mut dyn Vm<Binary>,
    j0: CtrBlock<Nonce, Ctr, Block>,
    explicit_nonce: [u8; 8],
) -> Result<(), AeadError> {
    vm.assign(j0.explicit_nonce, explicit_nonce)?;
    vm.commit(j0.explicit_nonce)?;
    vm.assign(j0.counter, 1u32.to_be_bytes())?;
    vm.commit(j0.counter)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        aead::{AeadInPlace, NewAead},
        Aes128Gcm,
    };
    use mpz_common::context::test_st_context;
    use mpz_core::Block;
    use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
    use mpz_memory_core::{binary::U8, correlated::Delta};
    use mpz_ot::ideal::cot::ideal_cot;
    use mpz_share_conversion::ideal::ideal_share_convert;
    use rand::{rngs::StdRng, SeedableRng};
    use rstest::*;

    static SHORT_MSG: &[u8] = b"hello world";
    static LONG_MSG: &[u8] = b"this message exceeds one block in length";

    #[derive(Clone, Copy)]
    struct Vars {
        key: Array<U8, 16>,
        iv: Array<U8, 4>,
    }

    #[rstest]
    #[case::short(SHORT_MSG, 1)]
    #[case::long(LONG_MSG, 1)]
    #[case::short_multiple(SHORT_MSG, 3)]
    #[case::long_multiple(LONG_MSG, 3)]
    #[tokio::test]
    async fn test_aes_gcm_encrypt(#[case] msg: &[u8], #[case] count: usize) {
        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let key = [42u8; 16];
        let iv = [0u8; 4];

        let ((mut vm_0, vars_0), (mut vm_1, vars_1)) = create_vm(key, iv);
        let (mut leader, mut follower) = create_pair(vars_0, vars_1);

        leader.alloc(&mut vm_0, count, 256).unwrap();
        follower.alloc(&mut vm_1, count, 256).unwrap();

        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

        tokio::try_join!(leader.setup(&mut ctx_0), follower.setup(&mut ctx_1)).unwrap();

        for i in 0u64..count as u64 {
            let explicit_nonce = i.to_be_bytes().to_vec();
            let (msg_0, ct_0) = leader
                .apply_keystream(&mut vm_0, explicit_nonce.clone(), msg.len())
                .unwrap();
            let (msg_1, ct_1) = follower
                .apply_keystream(&mut vm_1, explicit_nonce.clone(), msg.len())
                .unwrap();

            vm_0.assign(msg_0, msg.to_vec()).unwrap();
            vm_0.commit(msg_0).unwrap();

            vm_1.commit(msg_1).unwrap();

            let ct_0 = vm_0.decode(ct_0).unwrap();
            let ct_1 = vm_1.decode(ct_1).unwrap();

            run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

            let ct_0 = ct_0.await.unwrap();
            let ct_1 = ct_1.await.unwrap();

            let (expected, _) = expected(&key, &iv, &explicit_nonce, msg, &[]);
            assert_eq!(ct_0, expected);
            assert_eq!(ct_1, expected);
        }
    }

    #[rstest]
    #[case::short(SHORT_MSG, 1)]
    #[case::long(LONG_MSG, 1)]
    #[case::short_multiple(SHORT_MSG, 3)]
    #[case::long_multiple(LONG_MSG, 3)]
    #[tokio::test]
    async fn test_aes_gcm_decrypt(#[case] msg: &[u8], #[case] count: usize) {
        let (mut ctx_0, mut ctx_1) = test_st_context(8);

        let key = [42u8; 16];
        let iv = [0u8; 4];

        let ((mut vm_0, vars_0), (mut vm_1, vars_1)) = create_vm(key, iv);
        let (mut leader, mut follower) = create_pair(vars_0, vars_1);

        leader.alloc(&mut vm_0, count, 256).unwrap();
        follower.alloc(&mut vm_1, count, 256).unwrap();

        run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

        tokio::try_join!(leader.setup(&mut ctx_0), follower.setup(&mut ctx_1)).unwrap();

        for i in 0u64..count as u64 {
            let explicit_nonce = i.to_be_bytes().to_vec();
            let (ct, _) = expected(&key, &iv, &explicit_nonce, msg, &[]);

            let (ct_0, msg_0) = leader
                .apply_keystream(&mut vm_0, explicit_nonce.clone(), ct.len())
                .unwrap();
            let (ct_1, msg_1) = follower
                .apply_keystream(&mut vm_1, explicit_nonce.clone(), ct.len())
                .unwrap();

            vm_0.assign(ct_0, ct.clone()).unwrap();
            vm_0.commit(ct_0).unwrap();

            vm_1.commit(ct_1).unwrap();

            let msg_0 = vm_0.decode(msg_0).unwrap();
            let msg_1 = vm_1.decode(msg_1).unwrap();

            run_vms(&mut vm_0, &mut ctx_0, &mut vm_1, &mut ctx_1).await;

            let msg_0 = msg_0.await.unwrap();
            let msg_1 = msg_1.await.unwrap();

            assert_eq!(&msg_0, msg);
            assert_eq!(&msg_1, msg);
        }
    }

    fn create_vm(key: [u8; 16], iv: [u8; 4]) -> ((impl Vm<Binary>, Vars), (impl Vm<Binary>, Vars)) {
        let mut rng = StdRng::seed_from_u64(0);
        let block = Block::random(&mut rng);
        let (sender, receiver) = ideal_cot(block);

        let delta = Delta::new(block);
        let mut vm_0 = Garbler::new(sender, [0u8; 16], delta);
        let mut vm_1 = Evaluator::new(receiver);

        let key_ref_0 = vm_0.alloc::<Array<U8, 16>>().unwrap();
        vm_0.mark_public(key_ref_0).unwrap();
        vm_0.assign(key_ref_0, key).unwrap();
        vm_0.commit(key_ref_0).unwrap();

        let key_ref_1 = vm_1.alloc::<Array<U8, 16>>().unwrap();
        vm_1.mark_public(key_ref_1).unwrap();
        vm_1.assign(key_ref_1, key).unwrap();
        vm_1.commit(key_ref_1).unwrap();

        let iv_ref_0 = vm_0.alloc::<Array<U8, 4>>().unwrap();
        vm_0.mark_public(iv_ref_0).unwrap();
        vm_0.assign(iv_ref_0, iv).unwrap();
        vm_0.commit(iv_ref_0).unwrap();

        let iv_ref_1 = vm_1.alloc::<Array<U8, 4>>().unwrap();
        vm_1.mark_public(iv_ref_1).unwrap();
        vm_1.assign(iv_ref_1, iv).unwrap();
        vm_1.commit(iv_ref_1).unwrap();

        (
            (
                vm_0,
                Vars {
                    key: key_ref_0,
                    iv: iv_ref_0,
                },
            ),
            (
                vm_1,
                Vars {
                    key: key_ref_1,
                    iv: iv_ref_1,
                },
            ),
        )
    }

    fn create_pair(vars_0: Vars, vars_1: Vars) -> (MpcAesGcm, MpcAesGcm) {
        let mut rng = StdRng::seed_from_u64(0);
        let (c_0, c_1) = ideal_share_convert(Block::random(&mut rng));
        let mut leader = MpcAesGcm::new(c_0, Role::Leader);
        let mut follower = MpcAesGcm::new(c_1, Role::Follower);

        leader.set_key(vars_0.key);
        leader.set_iv(vars_0.iv);

        follower.set_key(vars_1.key);
        follower.set_iv(vars_1.iv);

        (leader, follower)
    }

    async fn run_vms(
        vm_0: &mut (dyn Vm<Binary> + Send),
        ctx_0: &mut Context,
        vm_1: &mut (dyn Vm<Binary> + Send),
        ctx_1: &mut Context,
    ) {
        tokio::join!(
            async {
                vm_0.execute_all(ctx_0).await.unwrap();
            },
            async {
                vm_1.execute_all(ctx_1).await.unwrap();
            }
        );
    }

    fn expected(
        key: &[u8],
        iv: &[u8],
        explicit_nonce: &[u8],
        msg: &[u8],
        aad: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let key: [u8; 16] = key.try_into().unwrap();
        let aes = Aes128Gcm::new(&key.into());

        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(iv);
        nonce[4..].copy_from_slice(explicit_nonce);

        let mut payload = msg.to_vec();
        let tag = aes
            .encrypt_in_place_detached(&nonce.into(), aad, &mut payload)
            .unwrap();

        (payload, tag.to_vec())
    }
}
