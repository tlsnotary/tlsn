//! The AES-128 block cipher.
//!
//! [`MpcAes`] implements [`crate::Cipher`] for AES-128 using [`Aes128`].

use crate::{circuit::CipherCircuit, Cipher, Keystream};
use async_trait::async_trait;
use mpz_memory_core::{binary::Binary, Repr, StaticSize};
use mpz_vm_core::{prelude::*, CallBuilder, Vm};
use std::{collections::VecDeque, fmt::Debug};

mod circuit;
mod error;

pub use circuit::Aes128;
use error::{AesError, ErrorKind};

/// Computes AES-128.
#[derive(Default)]
pub struct MpcAes {
    key: Option<<Aes128 as CipherCircuit>::Key>,
    iv: Option<<Aes128 as CipherCircuit>::Iv>,
}

impl Debug for MpcAes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAes")
            .field("key", &"{{...}}")
            .field("iv", &"{{...}}")
            .finish()
    }
}

impl MpcAes {
    fn alloc_public<R>(vm: &mut dyn Vm<Binary>) -> Result<R, AesError>
    where
        R: Repr<Binary> + StaticSize<Binary> + Copy,
    {
        let value = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        vm.mark_public(value)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(value)
    }
}

#[async_trait]
impl Cipher<Aes128> for MpcAes {
    type Error = AesError;

    fn set_key(&mut self, key: <Aes128 as CipherCircuit>::Key) {
        self.key = Some(key);
    }

    fn set_iv(&mut self, iv: <Aes128 as CipherCircuit>::Iv) {
        self.iv = Some(iv);
    }

    fn key(&self) -> Result<<Aes128 as CipherCircuit>::Key, Self::Error> {
        self.key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))
    }

    fn iv(&self) -> Result<<Aes128 as CipherCircuit>::Iv, Self::Error> {
        self.iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))
    }

    fn alloc(
        &self,
        vm: &mut dyn Vm<Binary>,
        block_count: usize,
    ) -> Result<Keystream<Aes128>, Self::Error> {
        let key = <Self as Cipher<Aes128>>::key(self)?;
        let iv = <Self as Cipher<Aes128>>::iv(self)?;

        let mut keystream = Keystream::<Aes128>::default();
        let mut circuits = VecDeque::with_capacity(block_count);

        // outputs need to be allocated sequentially so we do two separate for loops.
        for _ in 0..block_count {
            let explicit_nonce: <Aes128 as CipherCircuit>::Nonce = MpcAes::alloc_public(vm)?;
            let counter: <Aes128 as CipherCircuit>::Counter = MpcAes::alloc_public(vm)?;

            let aes_ctr = CallBuilder::new(<Aes128 as CipherCircuit>::ctr())
                .arg(key)
                .arg(iv)
                .arg(explicit_nonce)
                .arg(counter)
                .build()
                .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

            keystream.explicit_nonces.push_back(explicit_nonce);
            keystream.counters.push_back(counter);
            circuits.push_back(aes_ctr);
        }

        for _ in 0..block_count {
            let aes_ctr = circuits
                .pop_front()
                .expect("Enough aes-ctr circuits should be available");
            let output: <Aes128 as CipherCircuit>::Block = vm
                .call(aes_ctr)
                .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

            keystream.outputs.push_back(output);
        }

        Ok(keystream)
    }

    fn assign_block(
        &self,
        vm: &mut dyn Vm<Binary>,
        input_ref: <Aes128 as CipherCircuit>::Block,
        input: <<Aes128 as CipherCircuit>::Block as Repr<Binary>>::Clear,
    ) -> Result<<Aes128 as CipherCircuit>::Block, Self::Error> {
        let key = <Self as Cipher<Aes128>>::key(self)?;

        vm.assign(input_ref, input)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
        vm.commit(input_ref)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let aes_ecb = CallBuilder::new(<Aes128 as CipherCircuit>::ecb())
            .arg(key)
            .arg(input_ref)
            .build()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let output: <Aes128 as CipherCircuit>::Block = vm
            .call(aes_ecb)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aes::{Aes128, MpcAes},
        Cipher, Input,
    };
    use mpz_common::context::test_st_context;
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
    use mpz_memory_core::{
        binary::{Binary, U8},
        correlated::Delta,
        Array, MemoryExt, Vector, ViewExt,
    };
    use mpz_ot::ideal::cot::ideal_cot;
    use mpz_vm_core::{Execute, Vm};
    use rand::{rngs::StdRng, SeedableRng};

    #[tokio::test]
    async fn test_aes_ctr() {
        let key = [42_u8; 16];
        let iv = [3_u8; 4];
        let nonce = [5_u8; 8];
        let start_counter = 3;

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut gen, mut ev) = mock_vm();

        let aes_gen = setup_ctr(key, iv, &mut gen);
        let aes_ev = setup_ctr(key, iv, &mut ev);

        let msg = b"This is a test message which will be encrypted using AES-CTR.".to_vec();
        let block_count = (msg.len() / 16) + (msg.len() % 16 != 0) as usize;

        let keystream_gen = aes_gen.alloc(&mut gen, block_count).unwrap();
        let keystream_ev = aes_ev.alloc(&mut ev, block_count).unwrap();

        let msg_ref_gen: Vector<U8> = gen.alloc_vec(msg.len()).unwrap();
        gen.mark_public(msg_ref_gen).unwrap();

        let msg_ref_ev: Vector<U8> = ev.alloc_vec(msg.len()).unwrap();
        ev.mark_public(msg_ref_ev).unwrap();

        let cipher_out_gen = keystream_gen.apply(&mut gen, msg_ref_gen).unwrap();
        let cipher_out_ev = keystream_ev.apply(&mut ev, msg_ref_ev).unwrap();

        let out_gen = cipher_out_gen
            .assign(&mut gen, nonce, start_counter, Input::Message(msg.clone()))
            .unwrap();
        let out_ev = cipher_out_ev
            .assign(&mut ev, nonce, start_counter, Input::Message(msg.clone()))
            .unwrap();

        let (ciphertext_gen, ciphetext_ev) = tokio::try_join!(
            async {
                let out = gen.decode(out_gen).unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                out.await
            },
            async {
                let out = ev.decode(out_ev).unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                out.await
            }
        )
        .unwrap();

        assert_eq!(ciphertext_gen, ciphetext_ev);

        let expected = aes_apply_keystream(key, iv, nonce, start_counter as usize, msg);
        assert_eq!(ciphertext_gen, expected);
    }

    #[tokio::test]
    async fn test_aes_ecb() {
        let key = [1_u8; 16];
        let input = [5_u8; 16];

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut gen, mut ev) = mock_vm();

        let aes_gen = setup_block(key, &mut gen);
        let aes_ev = setup_block(key, &mut ev);

        let block_ref_gen: Array<U8, 16> = gen.alloc().unwrap();
        gen.mark_public(block_ref_gen).unwrap();

        let block_ref_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_public(block_ref_ev).unwrap();

        let block_gen = aes_gen
            .assign_block(&mut gen, block_ref_gen, input)
            .unwrap();
        let block_ev = aes_ev.assign_block(&mut ev, block_ref_ev, input).unwrap();

        let (ciphertext_gen, ciphetext_ev) = tokio::try_join!(
            async {
                let out = gen.decode(block_gen).unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                out.await
            },
            async {
                let out = ev.decode(block_ev).unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                out.await
            }
        )
        .unwrap();

        assert_eq!(ciphertext_gen, ciphetext_ev);

        let expected = aes128(key, input);
        assert_eq!(ciphertext_gen, expected);
    }

    fn mock_vm() -> (impl Vm<Binary> + Execute, impl Vm<Binary> + Execute) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }

    fn setup_ctr(key: [u8; 16], iv: [u8; 4], vm: &mut dyn Vm<Binary>) -> MpcAes {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let iv_ref: Array<U8, 4> = vm.alloc().unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(iv_ref, iv).unwrap();
        vm.commit(iv_ref).unwrap();

        let mut aes = MpcAes::default();

        Cipher::<Aes128>::set_key(&mut aes, key_ref);
        Cipher::<Aes128>::set_iv(&mut aes, iv_ref);

        aes
    }

    fn setup_block(key: [u8; 16], vm: &mut dyn Vm<Binary>) -> MpcAes {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let mut aes = MpcAes::default();
        Cipher::<Aes128>::set_key(&mut aes, key_ref);

        aes
    }

    fn aes_apply_keystream(
        key: [u8; 16],
        iv: [u8; 4],
        explicit_nonce: [u8; 8],
        start_ctr: usize,
        msg: Vec<u8>,
    ) -> Vec<u8> {
        use ::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use aes::Aes128;
        use ctr::Ctr32BE;

        let mut full_iv = [0u8; 16];
        full_iv[0..4].copy_from_slice(&iv);
        full_iv[4..12].copy_from_slice(&explicit_nonce);

        let mut cipher = Ctr32BE::<Aes128>::new(&key.into(), &full_iv.into());
        let mut out = msg.clone();

        cipher
            .try_seek(start_ctr * 16)
            .expect("start counter is less than keystream length");
        cipher.apply_keystream(&mut out);

        out
    }

    fn aes128(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
        use ::aes::Aes128 as TestAes128;
        use ::cipher::{BlockEncrypt, KeyInit};

        let mut msg = msg.into();
        let cipher = TestAes128::new(&key.into());
        cipher.encrypt_block(&mut msg);
        msg.into()
    }
}
