//! The AES-128 block cipher.

use crate::{Cipher, CtrBlock, Keystream};
use async_trait::async_trait;
use mpz_memory_core::binary::{Binary, U8};
use mpz_vm_core::{prelude::*, Call, Vm};
use std::fmt::Debug;

mod circuit;
mod error;

pub use error::AesError;
use error::ErrorKind;

/// Computes AES-128.
#[derive(Default, Debug)]
pub struct Aes128 {
    key: Option<Array<U8, 16>>,
    iv: Option<Array<U8, 4>>,
}

#[async_trait]
impl Cipher for Aes128 {
    type Error = AesError;
    type Key = Array<U8, 16>;
    type Iv = Array<U8, 4>;
    type Nonce = Array<U8, 8>;
    type Counter = Array<U8, 4>;
    type Block = Array<U8, 16>;

    fn set_key(&mut self, key: Array<U8, 16>) {
        self.key = Some(key);
    }

    fn set_iv(&mut self, iv: Array<U8, 4>) {
        self.iv = Some(iv);
    }

    fn key(&self) -> Option<&Array<U8, 16>> {
        self.key.as_ref()
    }

    fn iv(&self) -> Option<&Array<U8, 4>> {
        self.iv.as_ref()
    }

    fn alloc_block(
        &self,
        vm: &mut dyn Vm<Binary>,
        input: Array<U8, 16>,
    ) -> Result<Self::Block, Self::Error> {
        let key = self
            .key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;

        let output = vm
            .call(
                Call::builder(circuit::AES128_ECB.clone())
                    .arg(key)
                    .arg(input)
                    .build()
                    .expect("call should be valid"),
            )
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(output)
    }

    fn alloc_ctr_block(
        &self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<CtrBlock<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        let key = self
            .key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;
        let iv = self
            .iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))?;

        let explicit_nonce: Array<U8, 8> = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
        vm.mark_public(explicit_nonce)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let counter: Array<U8, 4> = vm
            .alloc()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
        vm.mark_public(counter)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let output = vm
            .call(
                Call::builder(circuit::AES128_CTR.clone())
                    .arg(key)
                    .arg(iv)
                    .arg(explicit_nonce)
                    .arg(counter)
                    .build()
                    .expect("call should be valid"),
            )
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok(CtrBlock {
            explicit_nonce,
            counter,
            output,
        })
    }

    fn alloc_keystream(
        &self,
        vm: &mut dyn Vm<Binary>,
        len: usize,
    ) -> Result<Keystream<Self::Nonce, Self::Counter, Self::Block>, Self::Error> {
        let key = self
            .key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))?;
        let iv = self
            .iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))?;

        let block_count = len.div_ceil(16);

        let inputs = (0..block_count)
            .map(|_| {
                let explicit_nonce: Array<U8, 8> = vm
                    .alloc()
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
                let counter: Array<U8, 4> = vm
                    .alloc()
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

                vm.mark_public(explicit_nonce)
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;
                vm.mark_public(counter)
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

                Ok((explicit_nonce, counter))
            })
            .collect::<Result<Vec<_>, AesError>>()?;

        let blocks = inputs
            .into_iter()
            .map(|(explicit_nonce, counter)| {
                let output = vm
                    .call(
                        Call::builder(circuit::AES128_CTR.clone())
                            .arg(key)
                            .arg(iv)
                            .arg(explicit_nonce)
                            .arg(counter)
                            .build()
                            .expect("call should be valid"),
                    )
                    .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

                Ok(CtrBlock {
                    explicit_nonce,
                    counter,
                    output,
                })
            })
            .collect::<Result<Vec<_>, AesError>>()?;

        Ok(Keystream::new(&blocks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cipher;
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
        let start_counter = 3u32;

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut gen, mut ev) = mock_vm();

        let aes_gen = setup_ctr(key, iv, &mut gen);
        let aes_ev = setup_ctr(key, iv, &mut ev);

        let msg = vec![42u8; 128];

        let keystream_gen = aes_gen.alloc_keystream(&mut gen, msg.len()).unwrap();
        let keystream_ev = aes_ev.alloc_keystream(&mut ev, msg.len()).unwrap();

        let msg_ref_gen: Vector<U8> = gen.alloc_vec(msg.len()).unwrap();
        gen.mark_public(msg_ref_gen).unwrap();
        gen.assign(msg_ref_gen, msg.clone()).unwrap();
        gen.commit(msg_ref_gen).unwrap();

        let msg_ref_ev: Vector<U8> = ev.alloc_vec(msg.len()).unwrap();
        ev.mark_public(msg_ref_ev).unwrap();
        ev.assign(msg_ref_ev, msg.clone()).unwrap();
        ev.commit(msg_ref_ev).unwrap();

        let mut ctr = start_counter..;
        keystream_gen
            .assign(&mut gen, nonce, move || ctr.next().unwrap().to_be_bytes())
            .unwrap();
        let mut ctr = start_counter..;
        keystream_ev
            .assign(&mut ev, nonce, move || ctr.next().unwrap().to_be_bytes())
            .unwrap();

        let cipher_out_gen = keystream_gen.apply(&mut gen, msg_ref_gen).unwrap();
        let cipher_out_ev = keystream_ev.apply(&mut ev, msg_ref_ev).unwrap();

        let (ct_gen, ct_ev) = tokio::try_join!(
            async {
                let out = gen.decode(cipher_out_gen).unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                gen.execute(&mut ctx_a).await.unwrap();
                gen.flush(&mut ctx_a).await.unwrap();
                out.await
            },
            async {
                let out = ev.decode(cipher_out_ev).unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                ev.execute(&mut ctx_b).await.unwrap();
                ev.flush(&mut ctx_b).await.unwrap();
                out.await
            }
        )
        .unwrap();

        assert_eq!(ct_gen, ct_ev);

        let expected = aes_apply_keystream(key, iv, nonce, start_counter as usize, msg);
        assert_eq!(ct_gen, expected);
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
        gen.assign(block_ref_gen, input).unwrap();
        gen.commit(block_ref_gen).unwrap();

        let block_ref_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_public(block_ref_ev).unwrap();
        ev.assign(block_ref_ev, input).unwrap();
        ev.commit(block_ref_ev).unwrap();

        let block_gen = aes_gen.alloc_block(&mut gen, block_ref_gen).unwrap();
        let block_ev = aes_ev.alloc_block(&mut ev, block_ref_ev).unwrap();

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

    fn mock_vm() -> (impl Vm<Binary>, impl Vm<Binary>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }

    fn setup_ctr(key: [u8; 16], iv: [u8; 4], vm: &mut dyn Vm<Binary>) -> Aes128 {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let iv_ref: Array<U8, 4> = vm.alloc().unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(iv_ref, iv).unwrap();
        vm.commit(iv_ref).unwrap();

        let mut aes = Aes128::default();

        aes.set_key(key_ref);
        aes.set_iv(iv_ref);

        aes
    }

    fn setup_block(key: [u8; 16], vm: &mut dyn Vm<Binary>) -> Aes128 {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let mut aes = Aes128::default();
        aes.set_key(key_ref);

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
