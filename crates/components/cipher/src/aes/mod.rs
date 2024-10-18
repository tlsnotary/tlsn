//! The AES-128 block cipher.
//!
//! [`MpcAes`] implements [`crate::Cipher`] for AES-128 using [`Aes128`].

use crate::{
    circuit::CipherCircuit, config::CipherConfig, Cipher, CipherError, CipherOutput, Keystream,
};
use async_trait::async_trait;
use mpz_memory_core::{
    binary::{Binary, U8},
    MemoryExt, Repr, StaticSize, Vector, View, ViewExt,
};
use mpz_vm_core::{CallBuilder, Vm, VmExt};
use std::{collections::VecDeque, fmt::Debug};

mod circuit;
mod error;

pub use circuit::Aes128;
use error::{AesError, ErrorKind};

/// Computes AES-128.
pub struct MpcAes {
    config: CipherConfig,
    key: Option<<Aes128 as CipherCircuit>::Key>,
    iv: Option<<Aes128 as CipherCircuit>::Iv>,
}

impl Debug for MpcAes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcAes")
            .field("config", &self.config)
            .field("key", &"{{...}}")
            .field("iv", &"{{...}}")
            .finish()
    }
}

impl MpcAes {
    /// Creates a new instance.
    pub fn new(config: CipherConfig) -> Self {
        Self {
            config,
            key: None,
            iv: None,
        }
    }

    /// Returns the key reference.
    pub fn key(&self) -> Result<<Aes128 as CipherCircuit>::Key, AesError> {
        self.key
            .ok_or_else(|| AesError::new(ErrorKind::Key, "key not set"))
    }

    /// Returns the iv reference.
    pub fn iv(&self) -> Result<<Aes128 as CipherCircuit>::Iv, AesError> {
        self.iv
            .ok_or_else(|| AesError::new(ErrorKind::Iv, "iv not set"))
    }

    fn alloc_public<R, V>(vm: &mut V) -> Result<R, AesError>
    where
        R: Repr<Binary> + StaticSize<Binary> + Copy,
        V: View<Binary> + Vm<Binary>,
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
impl<V> Cipher<Aes128, V> for MpcAes
where
    V: Vm<Binary> + View<Binary>,
{
    type Error = AesError;

    fn set_key(&mut self, key: <Aes128 as CipherCircuit>::Key) {
        self.key = Some(key);
    }

    fn set_iv(&mut self, iv: <Aes128 as CipherCircuit>::Iv) {
        self.iv = Some(iv);
    }

    fn alloc(&self, vm: &mut V, block_count: usize) -> Result<Keystream<Aes128>, Self::Error> {
        let key = self.key()?;
        let iv = self.iv()?;

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
        vm: &mut V,
        input_ref: <Aes128 as CipherCircuit>::Block,
        input: <<Aes128 as CipherCircuit>::Block as Repr<Binary>>::Clear,
    ) -> Result<<Aes128 as CipherCircuit>::Block, Self::Error> {
        let key = self.key()?;

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

impl CipherOutput<Aes128> {
    /// Assigns values to the input references and returns the output reference.
    ///
    /// # Arguments
    ///
    /// * `vm` - The necessary virtual machine.
    /// * `explicit_nonce` - The TLS explicit nonce.
    /// * `start_ctr` - The TLS counter number to start with.
    /// * `message` - The message to en-/decrypt.
    pub fn assign<V>(
        self,
        vm: &mut V,
        explicit_nonce: [u8; 8],
        start_ctr: u32,
        message: Vec<u8>,
    ) -> Result<Vector<U8>, CipherError>
    where
        V: Vm<Binary>,
    {
        if self.len() != message.len() {
            return Err(CipherError::new(format!(
                "message has wrong length, got {}, but expected {}",
                message.len(),
                self.len()
            )));
        }

        let message_len = message.len() as u32;
        let block_count = (message_len / 16) + (message_len % 16 != 0) as u32;
        let counters = (start_ctr..start_ctr + block_count).map(|counter| counter.to_be_bytes());

        for ((ctr, ctr_value), nonce) in self
            .counters
            .into_iter()
            .zip(counters)
            .zip(self.explicit_nonces)
        {
            vm.assign(ctr, ctr_value).map_err(CipherError::new)?;
            vm.commit(ctr).map_err(CipherError::new)?;

            vm.assign(nonce, explicit_nonce).map_err(CipherError::new)?;
            vm.commit(nonce).map_err(CipherError::new)?;
        }

        vm.assign(self.input, message).map_err(CipherError::new)?;
        vm.commit(self.input).map_err(CipherError::new)?;

        Ok(self.output)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aes::{Aes128, MpcAes},
        Cipher, CipherConfig,
    };
    use mpz_common::{
        executor::{test_st_executor, TestSTExecutor},
        Context,
    };
    use mpz_garble::protocol::semihonest::{Evaluator, Generator};
    use mpz_memory_core::{
        binary::{Binary, U8},
        correlated::Delta,
        Array, Memory, MemoryExt, Vector, View, ViewExt,
    };
    use mpz_ot::ideal::cot::ideal_cot_with_delta;
    use mpz_vm_core::{Execute, Vm};
    use rand::{rngs::StdRng, SeedableRng};

    #[tokio::test]
    async fn test_aes_ctr() {
        let key = [42_u8; 16];
        let iv = [3_u8; 4];
        let nonce = [5_u8; 8];
        let start_counter = 3;

        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm::<TestSTExecutor>();

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
            .assign(&mut gen, nonce, start_counter, msg.clone())
            .unwrap();
        let out_ev = cipher_out_ev
            .assign(&mut ev, nonce, start_counter, msg.clone())
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

        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut gen, mut ev) = mock_vm::<TestSTExecutor>();

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

    fn mock_vm<Ctx>() -> (
        impl Vm<Binary> + View<Binary> + Execute<Ctx>,
        impl Vm<Binary> + View<Binary> + Execute<Ctx>,
    )
    where
        Ctx: Context,
    {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

        let gen = Generator::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }

    fn setup_ctr<V, Ctx>(key: [u8; 16], iv: [u8; 4], vm: &mut V) -> MpcAes
    where
        V: Vm<Binary> + Memory<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let iv_ref: Array<U8, 4> = vm.alloc().unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(iv_ref, iv).unwrap();
        vm.commit(iv_ref).unwrap();

        let config = CipherConfig::builder().id("test").build().unwrap();

        let mut aes = MpcAes::new(config);

        Cipher::<Aes128, V>::set_key(&mut aes, key_ref);
        Cipher::<Aes128, V>::set_iv(&mut aes, iv_ref);

        aes
    }

    fn setup_block<V, Ctx>(key: [u8; 16], vm: &mut V) -> MpcAes
    where
        V: Vm<Binary> + Memory<Binary> + View<Binary> + Execute<Ctx>,
        Ctx: Context,
    {
        let key_ref: Array<U8, 16> = vm.alloc().unwrap();
        vm.mark_public(key_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.commit(key_ref).unwrap();

        let config = CipherConfig::builder().id("test").build().unwrap();
        let mut aes = MpcAes::new(config);
        Cipher::<Aes128, V>::set_key(&mut aes, key_ref);

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
